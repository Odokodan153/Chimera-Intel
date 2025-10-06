"""
Radio Frequency (RF) Analysis (SIGINT) Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import numpy as np
import pymodes as pm
import os
import subprocess
import json
from rich.console import Console
from rich.table import Table

console = Console()

# Create a new Typer application for SIGINT commands


sigint_app = typer.Typer(
    name="sigint",
    help="Radio Frequency (RF) Analysis (SIGINT)",
)


def decode_adsb_from_capture(capture_path: str):
    """
    Decodes ADS-B messages from a raw I/Q signal capture file.
    """
    console.print(f"[cyan]Decoding ADS-B signals from {capture_path}...[/cyan]")
    # Read the raw I/Q data from the file

    try:
        iq_samples = np.fromfile(capture_path, dtype=np.complex64)
        magnitude = np.abs(iq_samples)
        messages = pm.demod.decode(magnitude, "long")

        if not messages:
            console.print(
                "[yellow]No ADS-B messages could be decoded from the capture.[/yellow]"
            )
            return
        table = Table(title="Decoded ADS-B Messages")
        table.add_column("ICAO ID", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Information", style="green")

        for msg, ts in messages:
            df = pm.df(msg)
            icao = pm.icao(msg)
            msg_type = f"DF{df} - {pm.decoder.df_str.get(df, 'Unknown')}"
            info = ""

            if df == 17:  # Extended Squitter
                tc = pm.adsb.typecode(msg)
                if 1 <= tc <= 4:
                    info = f"Callsign: {pm.adsb.callsign(msg).strip('_')}"
                elif 9 <= tc <= 18:
                    alt = pm.adsb.alt(msg)
                    lat, lon = pm.adsb.latlon(msg)
                    info = f"Position: Lat={lat:.4f}, Lon={lon:.4f}, Alt={alt} ft"
                elif tc == 19:
                    velocity = pm.adsb.velocity(msg)
                    info = (
                        f"Velocity: {velocity[0]:.2f} kts, Heading: {velocity[1]:.2f}°"
                    )
            elif df == 20 or df == 21:  # Comm-B
                bds = pm.bds.bds_commb(msg)
                if bds:
                    info = f"BDS Data: {bds}"
            if info:
                table.add_row(icao, msg_type, info)
        console.print(table)
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during ADS-B decoding: {e}[/bold red]"
        )


def decode_ais_from_capture(capture_path: str):
    """
    Decodes AIS messages from a raw signal capture using the rtl_ais tool.
    This function requires rtl_ais to be installed and in the system's PATH.
    """
    console.print(
        f"[cyan]Decoding AIS signals from {capture_path} using rtl_ais...[/cyan]"
    )
    try:
        # The command pipes the raw capture file into rtl_ais

        command = "rtl_sdr -f 162.025M -s 24000 - | rtl_ais -n"
        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,  # Add a timeout as it might run indefinitely
        )

        if process.returncode != 0 and process.stderr:
            if "not found" in process.stderr.lower():
                raise FileNotFoundError(
                    "rtl_ais command not found. Please ensure it is installed and in your PATH."
                )
            raise Exception(f"rtl_ais error: {process.stderr}")
        messages = process.stdout.strip().splitlines()
        if not messages:
            console.print(
                "[yellow]No AIS messages could be decoded from the capture.[/yellow]"
            )
            return
        table = Table(title="Decoded AIS Messages")
        table.add_column("MMSI", style="cyan")
        table.add_column("Message Type", style="magenta")
        table.add_column("Details", style="green")

        for msg_json in messages:
            try:
                msg = json.loads(msg_json)
                msg_type = msg.get("class")
                mmsi = msg.get("mmsi")
                details = ""
                if msg_type == "AIS:PositionReport":
                    details = f"Lat: {msg.get('lat', 'N/A')}, Lon: {msg.get('lon', 'N/A')}, SOG: {msg.get('speed_over_ground', 'N/A')} kts"
                elif msg_type == "AIS:StaticDataReport":
                    details = f"Name: {msg.get('shipname', 'N/A')}, Type: {msg.get('shiptype_text', 'N/A')}"
                if mmsi and details:
                    table.add_row(str(mmsi), msg_type, details)
            except json.JSONDecodeError:
                continue  # Ignore lines that are not valid JSON
        console.print(table)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during AIS decoding: {e}[/bold red]"
        )


@sigint_app.command(
    name="decode-capture", help="Decode signals from a raw SDR capture file."
)
def decode_capture(
    capture_file: Annotated[
        str,
        typer.Argument(help="Path to the raw signal capture file (e.g., .cu8)."),
    ],
    protocol: Annotated[
        str,
        typer.Option(
            "--protocol",
            "-p",
            help="The RF protocol to decode (e.g., adsb, ais).",
            prompt="Enter the protocol to decode",
        ),
    ],
):
    """
    Analyzes a raw radio signal capture to identify and decode wireless
    communications and device signals.
    """
    console.print(f"Decoding '{protocol.upper()}' signals from: {capture_file}")

    if not os.path.exists(capture_file):
        console.print(f"Error: Capture file not found at '{capture_file}'")
        raise typer.Exit(code=1)
    if protocol.lower() == "adsb":
        decode_adsb_from_capture(capture_file)
    elif protocol.lower() == "ais":
        decode_ais_from_capture(capture_file)
    else:
        console.print(f"Error: Protocol '{protocol}' is not currently supported.")
        raise typer.Exit(code=1)
    console.print("\nSignal analysis complete.")


if __name__ == "__main__":
    sigint_app()
