"""
Advanced Network Traffic Analysis Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from scapy.all import rdpcap, Raw
from scapy.layers.inet import TCP
import os

# Create a new Typer application for Traffic Analysis commands

traffic_analyzer_app = typer.Typer(
    name="traffic",
    help="Advanced Network Traffic Analysis (SIGINT)",
)


def carve_files_from_pcap(pcap_path: str, output_dir: str):
    """
    Carves files from unencrypted protocols (HTTP) in a PCAP file.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    packets = rdpcap(pcap_path)
    sessions = packets.sessions()

    carved_files = 0
    for session in sessions:
        http_payload = b""
        for packet in sessions[session]:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                # Simple check for HTTP GET/POST requests

                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_payload += packet[Raw].load
        if http_payload:
            try:
                # Naive check for HTTP headers and splitting content

                headers, content = http_payload.split(b"\r\n\r\n", 1)
                if content:
                    # A more robust implementation would parse Content-Disposition

                    filename = f"carved_file_{carved_files}.bin"
                    filepath = os.path.join(output_dir, filename)
                    with open(filepath, "wb") as f:
                        f.write(content)
                    print(f"Carved file: {filepath}")
                    carved_files += 1
            except ValueError:
                continue  # No valid HTTP header/body split
    if carved_files == 0:
        print("No files could be carved from the capture.")


@traffic_analyzer_app.command(
    name="analyze", help="Analyze a network traffic capture file."
)
def analyze_traffic(
    capture_file: Annotated[
        str,
        typer.Argument(help="Path to the network capture file (.pcap or .pcapng)."),
    ],
    carve_files: Annotated[
        bool,
        typer.Option(
            "--carve-files",
            "-c",
            help="Attempt to carve files from unencrypted traffic.",
        ),
    ] = False,
):
    """
    Analyzes raw network traffic captures to extract files and identify
    covert communication channels.
    """
    print(f"Analyzing network traffic from: {capture_file}")

    if not os.path.exists(capture_file):
        print(f"Error: Capture file not found at '{capture_file}'")
        raise typer.Exit(code=1)
    if carve_files:
        output_dir = "carved_files_output"
        print(f"Carving files to directory: {output_dir}")
        try:
            carve_files_from_pcap(capture_file, output_dir)
        except Exception as e:
            print(f"An error occurred during file carving: {e}")
            raise typer.Exit(code=1)
    # In a full implementation, you would add protocol dissection and
    # communication mapping features here.

    print("\nTraffic analysis complete.")


if __name__ == "__main__":
    traffic_analyzer_app()
