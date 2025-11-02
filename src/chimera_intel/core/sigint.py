import time
import typer
import socket
import csv
from typing import Dict, Any, Optional, List
import json

# ADS-B and Mode-S decoding

import pyModeS as pms
from pyModeS.decoder import adsb, commb

# AIS decoding

import pyais

# --- New Imports for SIGINT Expansion ---
import httpx
import whois
import dns.resolver
import ssl

try:
    from scapy.all import rdpcap
except ImportError:
    print(
        "Scapy not installed. Network traffic modeling will not be available. "
        "Please run: pip install scapy"
    )
    # Define a placeholder if scapy is not present
    def rdpcap(filename):
        raise ImportError("Please install scapy to use network traffic modeling.")


# --- End New Imports ---


# --- FIX: Import Console locally and remove from utils import ---
from rich.console import Console
from chimera_intel.core.utils import save_or_print_results

# --- End Fix ---
from chimera_intel.core.database import save_scan_to_db

# --- FIX: Create local console instance for proper capsys capture ---
# --- FIX 2: Set a large width to prevent text-wrapping in test assertions ---
console = Console(width=200)
# --- End Fix ---


class SignalIntercept:
    """A class to handle Mode-S signal interception and decoding."""

    def __init__(self, ref_lat: float, ref_lon: float):
        self.aircraft: Dict[str, Dict[str, Any]] = {}
        self.ref_lat = ref_lat
        self.ref_lon = ref_lon

    def update_aircraft_position(self, icao: str, lat: float, lon: float, t: float):
        """Updates the position of a known aircraft."""
        # Use setdefault to ensure the icao key exists before updating its value
        self.aircraft.setdefault(icao, {})
        self.aircraft[icao]["lat"] = lat
        self.aircraft[icao]["lon"] = lon
        self.aircraft[icao]["last_pos_update"] = t

    def update_aircraft_altitude(self, icao: str, alt: Optional[int], t: float):
        """Updates the altitude of a known aircraft."""
        # Use setdefault to ensure the icao key exists before updating its value
        self.aircraft.setdefault(icao, {})
        self.aircraft[icao]["altitude"] = alt
        self.aircraft[icao]["last_alt_update"] = t

    def update_aircraft_velocity(
        self,
        icao: str,
        spd: Optional[float],
        hdg: Optional[float],
        vr: Optional[int],
        t: float,
    ):
        """Updates the velocity of a known aircraft."""
        # Use setdefault to ensure the icao key exists before updating its value
        self.aircraft.setdefault(icao, {})
        self.aircraft[icao]["speed"] = spd
        self.aircraft[icao]["heading"] = hdg
        self.aircraft[icao]["vert_rate"] = vr
        self.aircraft[icao]["last_vel_update"] = t

    def process_message(self, msg: str, t: float):
        """Processes a single Mode-S message using the updated pyModeS API."""
        if len(msg) < 14:
            return
        df = pms.df(msg)
        icao = pms.icao(msg)

        if not icao:
            return

        # Removed redundant aircraft initialization: the update methods use setdefault
        # or the direct callsign logic below uses setdefault. This prevents empty
        # dict entries for messages that contain no updatable data.

        if df == 17:  # ADS-B Message
            tc = adsb.typecode(msg)
            if tc is None:
                return
            if 1 <= tc <= 4:
                callsign = adsb.callsign(msg)
                self.aircraft.setdefault(icao, {})
                self.aircraft[icao]["callsign"] = callsign.strip("_")
            elif 5 <= tc <= 8:
                pos = adsb.surface_position_with_ref(msg, self.ref_lat, self.ref_lon)
                if pos:
                    self.update_aircraft_position(icao, pos[0], pos[1], t)
                spd, hdg, _, _ = adsb.surface_velocity(msg)
                self.update_aircraft_velocity(icao, spd, hdg, None, t)
            elif 9 <= tc <= 18:
                alt = adsb.altitude(msg)
                if alt is not None:
                    self.update_aircraft_altitude(icao, int(alt), t)
                pos = adsb.position_with_ref(msg, self.ref_lat, self.ref_lon)
                if pos and pos[0] is not None and pos[1] is not None:
                    self.update_aircraft_position(icao, pos[0], pos[1], t)
            elif tc == 19:
                vel = adsb.velocity(msg)
                if vel:
                    self.update_aircraft_velocity(icao, vel[0], vel[1], vel[2], t)
        elif df in [20, 21]:
            try:
                # Attempt to decode as a Comm-B message for aircraft identification (BDS 2,0)

                callsign = commb.cs20(msg)
                if callsign:
                    self.aircraft.setdefault(icao, {})
                    self.aircraft[icao]["callsign"] = callsign.strip("_")
            except Exception as e:
                # FIX: Use console.print for test compatibility and CLI consistency
                console.print(
                    f"[bold red]Could not decode Comm-B message for {icao}: {e}[/bold red]"
                )


def run_sigint_analysis(
    ref_lat: float, ref_lon: float, host: str, port: int, duration_seconds: int = 60
) -> Dict[str, Any]:
    """Monitors and decodes a live Mode-S TCP stream (e.g., from dump1090)."""
    console.print(
        f"[bold cyan]Starting live SIGINT analysis for {duration_seconds} seconds from {host}:{port}...[/bold cyan]"
    )
    interceptor = SignalIntercept(ref_lat=ref_lat, ref_lon=ref_lon)

    start_time = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.settimeout(1.0)  # Don't block forever
            while time.time() - start_time < duration_seconds:
                try:
                    data = s.recv(1024).decode("utf-8", errors="ignore")
                    # Beast format messages start with '*' and end with ';'

                    messages = data.strip().split(";")
                    for msg in messages:
                        if msg.startswith("*"):
                            interceptor.process_message(msg[1:], time.time())
                except socket.timeout:
                    continue  # No data received, just continue the loop
                except Exception as e:
                    # FIX: Use console.print for test compatibility and CLI consistency
                    console.print(
                        f"[bold red]Error processing stream data: {e}[/bold red]"
                    )
    except (socket.error, ConnectionRefusedError) as e:
        console.print(
            f"[bold red]Error connecting to stream at {host}:{port}: {e}[/bold red]"
        )
        return {}
    console.print("[bold green]Live SIGINT analysis complete.[/bold green]")
    return interceptor.aircraft


def decode_adsb_from_capture(
    file_path: str, ref_lat: float, ref_lon: float
) -> Dict[str, Any]:
    """Decodes ADS-B messages from a CSV capture file."""
    console.print(f"Decoding ADS-B data from {file_path}...")
    interceptor = SignalIntercept(ref_lat=ref_lat, ref_lon=ref_lon)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                # Nested try/except to gracefully handle malformed rows
                try:
                    timestamp, hex_msg = float(row[0]), row[1]
                    interceptor.process_message(hex_msg, timestamp)
                except IndexError:
                    continue
                except ValueError as e:
                    raise Exception(f"Malformed row: {row}. Error: {e}")

    except FileNotFoundError:
        console.print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
        return {}
    except Exception as e:
        console.print(
            f"[bold red]An error occurred while processing the file: {e}[/bold red]"
        )
        return {}
    console.print("[bold green]ADS-B capture file decoding complete.[/bold green]")
    return interceptor.aircraft


def decode_ais_from_capture(file_path: str) -> Dict[str, Any]:
    """Decodes AIS NMEA messages from a text or CSV capture file."""
    console.print(f"Decoding AIS data from {file_path}...")
    vessels = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    # pyais can decode raw NMEA sentences

                    msg = pyais.decode(line.strip().encode())
                    if msg and hasattr(msg, "mmsi"):
                        # MMSI as string for consistent JSON keys
                        vessels[str(msg.mmsi)] = msg.asdict()
                except Exception as e:
                    # FIX: Use console.print for test compatibility and CLI consistency
                    console.print(
                        f"[bold red]Could not decode AIS message: '{line.strip()}' - {e}[/bold red]"
                    )
    except FileNotFoundError:
        console.print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
        return {}
    except Exception as e:
        console.print(
            f"[bold red]An error occurred while processing the file: {e}[/bold red]"
        )
        return {}
    console.print("[bold green]AIS capture file decoding complete.[/bold green]")
    return vessels


# --- New SIGINT Functionality ---


def analyze_digital_fingerprint(target_domain: str) -> Dict[str, Any]:
    """
    Analyzes network metadata (DNS, WHOIS, SSL certs) for a target domain.
    """
    console.print(f"Analyzing digital fingerprint for {target_domain}...")
    fingerprint = {"domain": target_domain}

    # 1. WHOIS
    try:
        w = whois.whois(target_domain)
        fingerprint["whois"] = w
    except Exception as e:
        console.print(f"[bold red]WHOIS lookup failed: {e}[/bold red]")
        fingerprint["whois"] = f"Error: {e}"

    # 2. DNS
    dns_records = {}
    resolver = dns.resolver.Resolver()
    for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = resolver.resolve(target_domain, record_type)
            dns_records[record_type] = [r.to_text() for r in answers]
        except Exception as e:
            dns_records[record_type] = f"Error: {e}"
    fingerprint["dns"] = dns_records

    # 3. SSL Certificate
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target_domain) as ssock:
                cert = ssock.getpeercert()
                fingerprint["ssl_certificate"] = cert
    except Exception as e:
        console.print(f"[bold red]SSL certificate fetch failed: {e}[/bold red]")
        fingerprint["ssl_certificate"] = f"Error: {e}"

    # JA3/HASSH would require packet analysis (e.g., from Scapy) which is
    # much more involved than this metadata lookup.
    # This function provides the metadata clustering part.

    console.print("[bold green]Digital fingerprint analysis complete.[/bold green]")
    return fingerprint


def scan_telemetry_leakage(
    keywords: List[str],
) -> Dict[str, Any]:
    """
    Scans public sources for accidental telemetry or code leakage.
    """
    console.print(f"Scanning for telemetry leakage with keywords: {keywords}...")
    results = {"github": [], "pastebin": []}

    # Use httpx for async-capable HTTP requests
    client = httpx.Client(http2=True, timeout=10.0)
    
    # Note: A real-world implementation would require a GitHub token passed via headers
    # and a dedicated service for Pastebin monitoring.
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        # "Authorization": "token YOUR_GITHUB_TOKEN" # Add token here
    }


    # 1. Search GitHub Code
    try:
        search_query = "+".join([f'"{k}"' for k in keywords])
        url = f"https://api.github.com/search/code?q={search_query}"
        response = client.get(url, headers=headers)
        response.raise_for_status()
        gh_results = response.json()

        for item in gh_results.get("items", []):
            results["github"].append(
                {
                    "url": item.get("html_url"),
                    "repo": item.get("repository", {}).get("full_name"),
                    "file_path": item.get("path"),
                    "matches": [
                        match.get("fragment") for match in item.get("text_matches", [])
                    ],
                }
            )

    except Exception as e:
        console.print(f"[bold red]GitHub search failed: {e}[/bold red]")
        results["github"] = f"Error: {e}"

    # 2. Search Pastebin (Simulated)
    # A real implementation would use a service that legally monitors pastes.
    try:
        console.print(
            "[bold yellow]Pastebin scan is simulated. "
            "Real-time public scraping is against ToS. "
            "A proper implementation requires a pro API key or monitoring service."
            "[/bold yellow]"
        )
        results["pastebin"] = "Simulated. No public API for keyword search."

    except Exception as e:
        results["pastebin"] = f"Error: {e}"

    client.close()
    console.print("[bold green]Telemetry leakage scan complete.[/bold green]")
    return results


def model_network_traffic(
    pcap_file_path: str, common_ports: Optional[List[int]] = None
) -> Dict[str, Any]:
    """
    Uses passive data (PCAP) to model common network behavior and flag deviations.
    """
    if common_ports is None:
        common_ports = [80, 443, 22, 53, 25, 110, 143, 993, 995]

    console.print(f"Modeling network traffic from {pcap_file_path}...")
    behavior = {
        "protocol_counts": {},
        "common_flows": {},
        "deviations": [],
    }

    try:
        packets = rdpcap(pcap_file_path)
    except FileNotFoundError:
        console.print(
            f"[bold red]Error: PCAP file not found at '{pcap_file_path}'[/bold red]"
        )
        return {}
    except Exception as e:
        console.print(f"[bold red]Error reading PCAP file: {e}[/bold red]")
        return {}

    for packet in packets:
        proto = None
        sport = None
        dport = None

        if "IP" in packet:
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst

            if "TCP" in packet:
                proto = "TCP"
                sport = packet["TCP"].sport
                dport = packet["TCP"].dport
            elif "UDP" in packet:
                proto = "UDP"
                sport = packet["UDP"].sport
                dport = packet["UDP"].dport
            elif "ICMP" in packet:
                proto = "ICMP"
            else:
                proto = packet["IP"].proto
        else:
            # Skip non-IP packets for this model
            continue

        if proto:
            behavior["protocol_counts"][proto] = (
                behavior["protocol_counts"].get(proto, 0) + 1
            )

        if sport is not None and dport is not None:
            flow = f"{proto} {ip_src}:{sport} -> {ip_dst}:{dport}"
            behavior["common_flows"][flow] = behavior["common_flows"].get(flow, 0) + 1

            # Check for deviations (non-standard port usage)
            if proto == "TCP" and (
                sport not in common_ports and dport not in common_ports
            ):
                deviation_msg = f"Potential deviation: {flow} (Non-standard ports)"
                if deviation_msg not in behavior["deviations"]:
                    behavior["deviations"].append(deviation_msg)
            elif proto == "UDP" and (
                sport not in common_ports and dport not in common_ports
            ):
                # High-port UDP is common, so we are less strict
                if sport > 1024 and dport > 1024:
                    pass  # Likely standard ephemeral port usage
                else:
                    deviation_msg = f"Potential deviation: {flow} (Non-standard ports)"
                    if deviation_msg not in behavior["deviations"]:
                        behavior["deviations"].append(deviation_msg)

    # Sort flows by frequency for clarity
    behavior["common_flows"] = dict(
        sorted(behavior["common_flows"].items(), key=lambda item: item[1], reverse=True)[
            :20
        ]
    )  # Top 20 flows

    console.print("[bold green]Network traffic modeling complete.[/bold green]")
    return behavior


def decode_amateur_radio_logs(file_path: str) -> Dict[str, Any]:
    """
    Decodes amateur radio logs (e.g., ADIF format, simplified parsing).
    An ADIF file looks like:
    <CALL:5>N0CALL <QSO_DATE:8>20251101 <TIME_ON:6>223000 <BAND:3>20M <MODE:3>SSB <EOR>
    """
    console.print(f"Decoding amateur radio (HAM) logs from {file_path}...")
    logs = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            log_id = 0
            # Read the whole file, ADIF records can span lines
            data = f.read()
            # Split records by <EOR> (End of Record)
            records = data.split("<EOR>")

            for record_data in records:
                if "<CALL:" not in record_data:
                    continue

                log_id += 1
                record = {}
                # Simple split to find tags
                parts = record_data.split("<")
                for part in parts:
                    if ":" in part and ">" in part:
                        try:
                            tag_full, value_dirty = part.split(">", 1)
                            tag_name, tag_len_str = tag_full.split(":", 1)
                            # Handle potential non-numeric length
                            if tag_len_str.isdigit():
                                tag_len = int(tag_len_str)
                                value = value_dirty[:tag_len].strip()
                                record[tag_name.upper()] = value
                        except Exception:
                            continue  # Malformed tag

                if "CALL" in record:
                    # Use callsign + log_id as a unique key
                    log_key = f"{record['CALL']}_{log_id}"
                    logs[log_key] = record

    except FileNotFoundError:
        console.print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
        return {}
    except Exception as e:
        console.print(
            f"[bold red]An error occurred while processing the file: {e}[/bold red]"
        )
        return {}
    console.print("[bold green]Amateur radio log decoding complete.[/bold green]")
    return logs


# --- Typer CLI Application ---


sigint_app = typer.Typer()


@sigint_app.command("live")
def run_live_scan(
    ref_lat: float = typer.Option(
        ..., "--lat", help="Reference latitude for position decoding."
    ),
    ref_lon: float = typer.Option(
        ..., "--lon", help="Reference longitude for position decoding."
    ),
    host: str = typer.Option(
        "127.0.0.1", "--host", help="Host of the ADS-B TCP stream."
    ),
    port: int = typer.Option(
        30005,
        "--port",
        help="Port of the ADS-B TCP stream (e.g., 30005 for Beast format).",
    ),
    duration: int = typer.Option(
        60, "--duration", "-d", help="Duration of the scan in seconds."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Monitors and decodes a live stream of aircraft signals (Mode-S/ADS-B)."""
    results = run_sigint_analysis(ref_lat, ref_lon, host, port, duration)
    final_results = {icao: data for icao, data in results.items() if data}

    if output_file:
        save_or_print_results(final_results, output_file)
    else:
        typer.echo(json.dumps(final_results, indent=2))
    if final_results:
        save_scan_to_db(
            target="live_aircraft_signals", module="sigint", data=final_results
        )


@sigint_app.command("decode-adsb")
def decode_adsb_file(
    capture_file: str = typer.Argument(
        ..., help="Path to the ADS-B CSV capture file (timestamp,hex_message)."
    ),
    ref_lat: float = typer.Option(
        ..., "--lat", help="Reference latitude for position decoding."
    ),
    ref_lon: float = typer.Option(
        ..., "--lon", help="Reference longitude for position decoding."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Decodes aircraft signals from a capture file."""
    results = decode_adsb_from_capture(capture_file, ref_lat, ref_lon)
    if not results:
        raise typer.Exit(code=1)
    final_results = {icao: data for icao, data in results.items() if data}

    if output_file:
        save_or_print_results(final_results, output_file)
    else:
        typer.echo(json.dumps(final_results, indent=2))
    if final_results:
        save_scan_to_db(
            target=capture_file, module="sigint_adsb_capture", data=final_results
        )


@sigint_app.command("decode-ais")
def decode_ais_file(
    capture_file: str = typer.Argument(
        ..., help="Path to the AIS NMEA capture file (one message per line)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Decodes maritime AIS signals from a capture file."""
    results = decode_ais_from_capture(capture_file)
    if not results:
        raise typer.Exit(code=1)
    if output_file:
        save_or_print_results(results, output_file)
    else:
        typer.echo(json.dumps(results, indent=2))
    if results:
        save_scan_to_db(target=capture_file, module="sigint_ais_capture", data=results)


@sigint_app.command("decode-ham")
def decode_ham_file(
    capture_file: str = typer.Argument(
        ..., help="Path to the amateur radio log file (e.g., adif.log)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Decodes amateur radio (HAM) logs from a capture file."""
    results = decode_amateur_radio_logs(capture_file)
    if not results:
        raise typer.Exit(code=1)
    if output_file:
        save_or_print_results(results, output_file)
    else:
        typer.echo(json.dumps(results, indent=2))
    if results:
        save_scan_to_db(target=capture_file, module="sigint_ham_capture", data=results)


@sigint_app.command("fingerprint")
def cli_analyze_digital_fingerprint(
    target_domain: str = typer.Argument(
        ..., help="The domain name to fingerprint (e.g., example.com)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Analyzes network metadata (DNS, WHOIS, SSL) for a target domain."""
    results = analyze_digital_fingerprint(target_domain)
    if not results:
        raise typer.Exit(code=1)

    # Handle non-serializable objects (like whois results) before saving/printing
    if "whois" in results and not isinstance(results["whois"], (str, dict)):
        results["whois"] = str(results["whois"])
    if "ssl_certificate" in results and not isinstance(
        results["ssl_certificate"], (str, dict)
    ):
        results["ssl_certificate"] = str(results["ssl_certificate"])

    if output_file:
        save_or_print_results(results, output_file)
    else:
        # Use default=str to handle any other non-serializable types gracefully
        typer.echo(json.dumps(results, indent=2, default=str))
    if results:
        save_scan_to_db(
            target=target_domain, module="sigint_fingerprint", data=results
        )


@sigint_app.command("scan-telemetry")
def cli_scan_telemetry_leakage(
    keywords: List[str] = typer.Argument(
        ..., help="List of keywords to search for (e.D., 'internal-api', 'dev-key')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Scans public sources (GitHub, Pastebin) for data leakage."""
    results = scan_telemetry_leakage(keywords)
    if not results:
        raise typer.Exit(code=1)

    if output_file:
        save_or_print_results(results, output_file)
    else:
        typer.echo(json.dumps(results, indent=2))
    if results:
        save_scan_to_db(
            target=",".join(keywords), module="sigint_telemetry_leak", data=results
        )


@sigint_app.command("model-traffic")
def cli_model_network_traffic(
    pcap_file: str = typer.Argument(
        ..., help="Path to the network capture file (e.g., capture.pcap)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Models network traffic from a PCAP file to find deviations."""
    try:
        results = model_network_traffic(pcap_file)
    except ImportError as e:
        console.print(f"[bold red]Failed to run: {e}[/bold red]")
        console.print("[bold yellow]Please ensure 'scapy' is installed: pip install scapy[/bold yellow]")
        raise typer.Exit(code=1)
        
    if not results:
        console.print("[bold yellow]No results generated from traffic model.[/bold yellow]")
        raise typer.Exit(code=1)

    if output_file:
        save_or_print_results(results, output_file)
    else:
        typer.echo(json.dumps(results, indent=2))
    if results:
        save_scan_to_db(
            target=pcap_file, module="sigint_traffic_model", data=results
        )


if __name__ == "__main__":
    sigint_app()