import time
import typer
import logging
import socket
import csv
from typing import Dict, Any, Optional
import json  # Import json here or inside each function

# ADS-B and Mode-S decoding

import pyModeS as pms
from pyModeS.decoder import adsb, commb

# AIS decoding

import pyais

from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db

logger = logging.getLogger(__name__)


class SignalIntercept:
    """A class to handle Mode-S signal interception and decoding."""

    def __init__(self, ref_lat: float, ref_lon: float):
        self.aircraft: Dict[str, Dict[str, Any]] = {}
        self.ref_lat = ref_lat
        self.ref_lon = ref_lon

    def update_aircraft_position(self, icao: str, lat: float, lon: float, t: float):
        """Updates the position of a known aircraft."""
        if icao not in self.aircraft:
            self.aircraft[icao] = {}
        self.aircraft[icao]["lat"] = lat
        self.aircraft[icao]["lon"] = lon
        self.aircraft[icao]["last_pos_update"] = t

    def update_aircraft_altitude(self, icao: str, alt: Optional[int], t: float):
        """Updates the altitude of a known aircraft."""
        if icao not in self.aircraft:
            self.aircraft[icao] = {}
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
        if icao not in self.aircraft:
            self.aircraft[icao] = {}
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
        if icao not in self.aircraft:
            self.aircraft[icao] = {}
        if df == 17:  # ADS-B Message
            tc = adsb.typecode(msg)
            if tc is None:
                return
            if 1 <= tc <= 4:
                callsign = adsb.callsign(msg)
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
                    self.aircraft[icao]["callsign"] = callsign.strip("_")
            except Exception as e:
                logger.debug(f"Could not decode Comm-B message for {icao}: {e}")


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
                    logger.error(f"Error processing stream data: {e}")
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
                timestamp, hex_msg = float(row[0]), row[1]
                interceptor.process_message(hex_msg, timestamp)
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
    # FIX: Change print to console.print for consistent output stream handling
    console.print(f"Decoding AIS data from {file_path}...")
    vessels = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    # pyais can decode raw NMEA sentences

                    msg = pyais.decode(line.strip().encode())
                    if msg and hasattr(msg, "mmsi"):
                        # FIX: For consistency with JSON keys and to avoid potential issues with int keys.
                        vessels[str(msg.mmsi)] = msg.asdict()
                except Exception as e:
                    logger.debug(
                        f"Could not decode AIS message: '{line.strip()}' - {e}"
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


if __name__ == "__main__":
    sigint_app()