"""
Radio Frequency (RF) Analysis (SIGINT) Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
import numpy as np
import pymodes as pm
import os

# Create a new Typer application for SIGINT commands

sigint_app = typer.Typer(
    name="sigint",
    help="Radio Frequency (RF) Analysis (SIGINT)",
)


def decode_adsb_from_capture(capture_path: str):
    """
    Decodes ADS-B messages from a raw I/Q signal capture file.
    """
    # Read the raw I/Q data from the file

    iq_samples = np.fromfile(capture_path, dtype=np.complex64)

    # The magnitude of the complex samples represents the signal power

    magnitude = np.abs(iq_samples)

    # Use pyModeS to decode messages from the signal magnitude
    # This is a simplified example; a real implementation would involve
    # more sophisticated signal processing.

    messages = pm.demod.decode(magnitude, "long")

    if not messages:
        print("No ADS-B messages could be decoded from the capture.")
        return
    print("\n--- Decoded ADS-B Messages ---")
    for msg, ts in messages:
        df = pm.df(msg)
        print(f"\nTimestamp: {ts}")
        print(f"  ICAO: {pm.icao(msg)}")
        print(f"  Type: DF{df} - {pm.decoder.df_str.get(df, 'Unknown')}")

        # Decode specific message types

        if df == 17:
            if pm.adsb.bds.bds_map.get(pm.adsb.typecode(msg)) == "BDS60":
                # Airborne position

                lat, lon = pm.adsb.latlon(msg)
                alt = pm.adsb.alt(msg)
                print(f"  Position: Lat={lat:.4f}, Lon={lon:.4f}, Alt={alt} ft")
            elif pm.adsb.bds.bds_map.get(pm.adsb.typecode(msg)) == "BDS05":
                # Aircraft identification

                callsign = pm.adsb.callsign(msg)
                print(f"  Callsign: {callsign.strip('_')}")
    print("----------------------------")


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
    print(f"Decoding '{protocol.upper()}' signals from: {capture_file}")

    if not os.path.exists(capture_file):
        print(f"Error: Capture file not found at '{capture_file}'")
        raise typer.Exit(code=1)
    if protocol.lower() == "adsb":
        try:
            decode_adsb_from_capture(capture_file)
        except Exception as e:
            print(f"An error occurred during ADS-B decoding: {e}")
            raise typer.Exit(code=1)
    else:
        print(f"Error: Protocol '{protocol}' is not currently supported.")
        # In a full implementation, you would add handlers for AIS, APRS, etc.

        raise typer.Exit(code=1)
    print("\nSignal analysis complete.")


if __name__ == "__main__":
    sigint_app()
