"""
Wireless Network Analysis (SIGINT) Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import os
import re

# Create a new Typer application for Wi-Fi Analysis commands

wifi_analyzer_app = typer.Typer(
    name="wifi",
    help="Wireless Network Analysis (SIGINT)",
)


def analyze_wifi_capture(pcap_path: str):
    """
    Parses a PCAP file to identify Wi-Fi networks and their security protocols.
    """
    packets = rdpcap(pcap_path)
    aps = {}

    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            ssid = packet[Dot11Elt].info.decode()

            if bssid not in aps:
                stats = packet[Dot11Beacon].network_stats()
                crypto = stats.get("crypto")

                # Determine security protocol

                security = "Open"
                if crypto:
                    if "WPA2" in crypto and "WPA" in crypto:
                        security = "WPA/WPA2"
                    elif "WPA2" in crypto:
                        security = "WPA2"
                    elif "WPA" in crypto:
                        security = "WPA"
                    elif "WEP" in crypto:
                        security = "WEP"
                aps[bssid] = {
                    "ssid": ssid,
                    "security": security,
                    "channel": stats.get("channel"),
                }
    if not aps:
        print("No Wi-Fi access points found in the capture file.")
        return
    print("\n--- Discovered Wi-Fi Networks ---")
    for bssid, info in aps.items():
        print(f"\nSSID: {info['ssid']}")
        print(f"  BSSID: {bssid}")
        print(f"  Channel: {info['channel']}")

        security_color = "green"
        if info["security"] in ["WEP", "Open"]:
            security_color = "red"
        elif info["security"] == "WPA":
            security_color = "yellow"
        print(f"  Security: [{security_color}]{info['security']}[/{security_color}]")
    print("---------------------------------")


@wifi_analyzer_app.command(
    name="analyze", help="Analyze a wireless network capture file."
)
def analyze_wifi(
    capture_file: Annotated[
        str,
        typer.Argument(help="Path to the wireless capture file (.pcap or .pcapng)."),
    ],
):
    """
    Analyzes wireless network capture files to identify, profile, and assess
    the security of Wi-Fi and Bluetooth devices.
    """
    print(f"Analyzing wireless networks from: {capture_file}")

    if not os.path.exists(capture_file):
        print(f"Error: Capture file not found at '{capture_file}'")
        raise typer.Exit(code=1)
    try:
        analyze_wifi_capture(capture_file)
    except Exception as e:
        print(f"An error occurred during Wi-Fi analysis: {e}")
        raise typer.Exit(code=1)
    print("\nWireless network analysis complete.")


if __name__ == "__main__":
    wifi_analyzer_app()
