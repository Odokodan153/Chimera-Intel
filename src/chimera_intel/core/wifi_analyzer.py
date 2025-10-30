import typer

# from typing_extensions import Annotated # <-- REVERTED
from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import os

# import sys  <-- FIX: Removed sys import
from rich.console import Console

# Create a console object
# --- FIX: Reverted force_terminal=True to allow plain-text output in capsys ---
console = Console()

# --- Logic Function ---


def analyze_wifi_capture(pcap_path: str):
    """
    Parses a PCAP file to identify Wi-Fi networks and their security protocols.
    """
    packets = rdpcap(pcap_path)
    aps = {}

    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2

            # --- FIX: Correctly parse SSID by ID, not just first Elt ---
            ssid = "<hidden>"  # Default if no SSID element
            ssid_elt = packet.getlayer(Dot11Elt, ID=0)  # ID 0 is for SSID
            if ssid_elt is not None:
                try:
                    ssid = ssid_elt.info.decode()
                except UnicodeDecodeError:
                    ssid = ssid_elt.info.hex()  # Fallback for undecodable SSIDs
            # --- End Fix ---

            if bssid not in aps:
                # --- START FIX: Manually parse crypto, network_stats() is unreliable ---
                stats = packet[Dot11Beacon].network_stats()  # Still use for channel

                crypto_set = set()

                # Check for RSN (WPA2/WPA3) - ID 48
                rsn_elt = packet.getlayer(Dot11Elt, ID=48)
                if rsn_elt:
                    crypto_set.add("WPA2")

                # Check for WPA1 (Vendor Specific) - ID 221
                # OUI for WPA is 00:50:F2, type 1
                wpa_elt = packet.getlayer(Dot11Elt, ID=221)
                if wpa_elt and wpa_elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
                    crypto_set.add("WPA")

                # Check for WEP (only if WPA/WPA2 not found)
                if packet[Dot11Beacon].cap.privacy and not crypto_set:
                    crypto_set.add("WEP")

                crypto = crypto_set
                # --- END FIX ---

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
        console.print("No Wi-Fi access points found in the capture file.")
        return
    console.print("\n--- Discovered Wi-Fi Networks ---")
    for bssid, info in aps.items():
        console.print(f"\nSSID: {info['ssid']}")
        console.print(f"  BSSID: {bssid}")
        # Note: Channel is often None without a proper RadioTap setup/parsing,
        # but the test logic is fine as is once the SSID is correct.
        channel_display = info["channel"] if info["channel"] is not None else "N/A"
        console.print(f"  Channel: {channel_display}")

        security_color = "green"
        if info["security"] in ["WEP", "Open"]:
            security_color = "red"
        elif info["security"] == "WPA":
            security_color = "yellow"
        # Use console.print to render the markup

        console.print(
            f"  Security: [{security_color}]{info['security']}[/{security_color}]"
        )
    console.print("---------------------------------")


# --- App Factory ---


def get_wifi_app():
    """
    Factory function to create the Wi-Fi Typer app.
    This prevents conflicts when testing or when using as a sub-app.
    """
    app = typer.Typer(
        help="Wireless Network Analysis (SIGINT)",
    )

    @app.command(help="Analyze a wireless network capture file.")
    def analyze(
        # --- START SYNTAX FIX: Removed invalid comments from function signature ---
        capture_file: str = typer.Argument(
            ..., help="Path to the wireless capture file (.pcap or .pcapng)."
        ),
        # --- END SYNTAX FIX ---
    ):
        """
        Analyzes wireless network capture files to identify, profile, and assess
        the security of Wi-Fi and Bluetooth devices.
        """
        console.print(f"Analyzing wireless networks from: {capture_file}")

        if not os.path.exists(capture_file):
            # FIX: Use console.print with rich markup and typer.Exit(1)
            console.print(
                f"[red]Error:[/red] Capture file not found at '{capture_file}'"
            )
            raise typer.Exit(code=1)
        try:
            # FIX: Corrected NameError (was pcap_path, should be capture_file)
            analyze_wifi_capture(capture_file)
        except Exception as e:
            # FIX: Use console.print with rich markup and typer.Exit(1)
            console.print(f"[red]An error occurred during Wi-Fi analysis:[/red] {e}")
            raise typer.Exit(code=1)

        # FIX: Added rich markup for success
        console.print("\n[green]Wireless network analysis complete.[/green]")

    return app


# Create a default instance for modules that import it (like a plugin)
wifi_analyzer_app = get_wifi_app()
