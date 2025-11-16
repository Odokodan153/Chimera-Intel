"""
SIGINT (Signals Intelligence) module for Chimera Intelligence Platform.
Provides functionalities for intercepting, decoding, and analyzing various
signal types including Mode-S/ADS-B, AIS, amateur radio logs,
digital fingerprinting, and network traffic modeling.
"""

import time
import typer
import socket
import csv
from typing import Dict, Any, Optional, List
import json
import logging
import asyncio
from chimera_intel.core.schemas import CellTowerInfo, RFSpectrumAnomaly, RFSpectrumReport
# ADS-B and Mode-S decoding
import pyModeS as pms
from pyModeS.decoder import adsb, commb
# AIS decoding
import pyais
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
from rich.console import Console
from chimera_intel.core.utils import save_or_print_results

from chimera_intel.core.database import save_scan_to_db

console = Console(width=200)


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

logger = logging.getLogger(__name__)

# OpenCelliD API endpoint
OPENCELLID_API_URL = "https://opencellid.org/cell/get"


async def get_cell_tower_info(
    mcc: int, mnc: int, lac: int, cid: int, api_key: str
) -> Dict[str, Any]:
    """
    Fetches cell tower location data from the OpenCelliD API.

    Args:
        mcc (int): Mobile Country Code (e.g., 234 for UK).
        mnc (int): Mobile Network Code (e.g., 15 for Vodafone UK).
        lac (int): Location Area Code.
        cid (int): Cell ID.
        api_key (str): OpenCelliD API Key.

    Returns:
        Dict[str, Any]: A dictionary containing the cell tower information or an error.
    """
    params = {
        "key": api_key,
        "mcc": mcc,
        "mnc": mnc,
        "lac": lac,
        "cellid": cid,
        "format": "json",
    }
    query_id = f"MCC:{mcc}, MNC:{mnc}, LAC:{lac}, CID:{cid}"
    console.print(f"Querying OpenCelliD for: {query_id}...")

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(OPENCELLID_API_URL, params=params)
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "error":
                error_msg = data.get("error", "Unknown API error")
                logger.warning(f"OpenCelliD API error for {query_id}: {error_msg}")
                return {"error": error_msg}

            # Validate and return the successful response
            # We can use our Pydantic schema for validation if one exists,
            # but for now, we'll return the raw valid dict.
            # Example validation:
            validated_data = CellTowerInfo.model_validate(data).model_dump()
            return validated_data

    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP error occurred: {e}"
        logger.error(error_msg)
        return {"error": error_msg}
    except asyncio.TimeoutError:
        error_msg = "OpenCelliD lookup timed out."
        logger.error(error_msg)
        return {"error": error_msg}
    except Exception as e:
        error_msg = f"An unexpected error occurred during cell tower lookup: {e}"
        logger.error(error_msg)
        return {"error": error_msg}

def monitor_rf_spectrum(
    host: str,
    port: int,
    duration_seconds: int,
    anomaly_threshold_dbm: float,
) -> RFSpectrumReport:
    """
    Monitors a live RF spectrum stream (e.g., from rtl_power)
    and detects signals exceeding a power threshold.

    Assumes stream format: 'timestamp,freq_start_hz,freq_end_hz,power_dbm'
    Example rtl_power command to generate such a stream (requires netcat):
    rtl_power -f 88M:108M:10k -g 30 -i 1 -P 1 | nc -l -p 1234
    """
    console.print(
        f"[bold cyan]Starting live RF spectrum analysis for {duration_seconds} seconds from {host}:{port}...[/bold cyan]"
    )
    console.print(
        f"  [bold]Anomaly Threshold:[/] {anomaly_threshold_dbm} dBm"
    )

    anomalies: List[RFSpectrumAnomaly] = []
    start_time = time.time()
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.settimeout(1.0)  # Don't block forever
            
            buffer = ""
            while time.time() - start_time < duration_seconds:
                try:
                    data = s.recv(1024).decode("utf-8", errors="ignore")
                    buffer += data
                    
                    # Process line by line
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line = line.strip()
                        if not line:
                            continue
                            
                        try:
                            # Expected format: 1678886400.0,88100000,88300000,-15.4
                            parts = line.split(',')
                            if len(parts) < 4:
                                continue
                                
                            ts = float(parts[0])
                            freq_start_hz = int(parts[1])
                            freq_end_hz = int(parts[2])
                            power = float(parts[3])
                            
                            # --- Spectrum Anomaly Detection ---
                            if power > anomaly_threshold_dbm:
                                freq_mhz = (freq_start_hz + (freq_end_hz - freq_start_hz) / 2) / 1_000_000
                                anomaly = RFSpectrumAnomaly(
                                    timestamp=ts,
                                    frequency_mhz=freq_mhz,
                                    power_dbm=power,
                                    details=f"Signal at {freq_mhz:.3f} MHz exceeded threshold of {anomaly_threshold_dbm} dBm"
                                )
                                anomalies.append(anomaly)
                                
                        except (ValueError, IndexError) as e:
                            # Gracefully handle malformed lines
                            console.print(f"[bold red]Error parsing spectrum data line: '{line}' - {e}[/bold red]")
                            
                except socket.timeout:
                    continue  # No data, continue loop
                except Exception as e:
                    console.print(f"[bold red]Error processing stream data: {e}[/bold red]")

    except (socket.error, ConnectionRefusedError) as e:
        console.print(f"[bold red]Error connecting to stream at {host}:{port}: {e}[/bold red]")
        return RFSpectrumReport(
            target_host=host,
            port=port,
            duration_seconds=duration_seconds,
            anomaly_threshold_dbm=anomaly_threshold_dbm,
            total_anomalies_found=0,
            error=str(e)
        )
    
    console.print("[bold green]Live RF spectrum analysis complete.[/bold green]")
    return RFSpectrumReport(
        target_host=host,
        port=port,
        duration_seconds=duration_seconds,
        anomaly_threshold_dbm=anomaly_threshold_dbm,
        total_anomalies_found=len(anomalies),
        anomalies=anomalies
    )

# --- Typer CLI Application ---


sigint_app = typer.Typer()

@sigint_app.command("monitor-spectrum")
def cli_monitor_spectrum(
    host: str = typer.Option(
        "127.0.0.1", "--host", help="Host of the RF spectrum TCP stream (e.g., from rtl_power)."
    ),
    port: int = typer.Option(
        1234, "--port", help="Port of the RF spectrum stream."
    ),
    duration: int = typer.Option(
        60, "--duration", "-d", help="Duration of the scan in seconds."
    ),
    threshold: float = typer.Option(
        -30.0, "--threshold", "-t", help="Power threshold (in dBm) to trigger an anomaly."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Monitors a live RF spectrum stream for signals exceeding a power threshold.
    Assumes stream format: 'timestamp,freq_start_hz,freq_end_hz,power_dbm'
    """
    results_model = monitor_rf_spectrum(host, port, duration, threshold)
    results_dict = results_model.model_dump(exclude_none=True)

    if output_file:
        save_or_print_results(results_dict, output_file)
    else:
        typer.echo(json.dumps(results_dict, indent=2))
    
    if results_model.anomalies:
        save_scan_to_db(
            target=f"{host}:{port}", module="sigint_spectrum_monitor", data=results_dict
        )

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