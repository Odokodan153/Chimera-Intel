"""
Advanced Network Traffic Analysis Module for Chimera Intel.
"""

import typer
from scapy.all import rdpcap, Raw
from scapy.layers.inet import TCP, IP
import os
from collections import Counter
from rich.console import Console
from rich.table import Table
import networkx as nx
from pyvis.network import Network

console = Console()

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
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_payload += packet[Raw].load
        if http_payload:
            try:
                # Find the end of headers

                header_end_index = http_payload.find(b"\r\n\r\n")
                if header_end_index != -1:
                    content = http_payload[header_end_index + 4 :]
                    if content:
                        filename = f"carved_file_{carved_files}.bin"
                        filepath = os.path.join(output_dir, filename)
                        with open(filepath, "wb") as f:
                            f.write(content)
                        console.print(f"Carved file: {filepath}")
                        carved_files += 1
            except ValueError:
                continue
    if carved_files == 0:
        console.print("No files could be carved from the capture.")


def analyze_protocols(pcap_path: str):
    """
    Dissects the pcap to provide a summary of protocols and conversations.
    """
    packets = rdpcap(pcap_path)
    protocol_counts = Counter(
        p.summary().split()[2] for p in packets if len(p.summary().split()) > 2
    )

    console.print("\n--- [bold green]Protocol Distribution[/bold green] ---")
    proto_table = Table(title="Protocol Summary")
    proto_table.add_column("Protocol", style="cyan")
    proto_table.add_column("Packet Count", style="magenta")
    for proto, count in protocol_counts.most_common():
        proto_table.add_row(proto, str(count))
    console.print(proto_table)

    G: nx.DiGraph = nx.DiGraph()
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if G.has_edge(src_ip, dst_ip):
                G[src_ip][dst_ip]["weight"] += 1
            else:
                G.add_edge(src_ip, dst_ip, weight=1)
    console.print("\n--- [bold green]Top Conversations[/bold green] ---")
    convo_table = Table(title="Top 10 IP Conversations")
    convo_table.add_column("Source IP", style="yellow")
    convo_table.add_column("Destination IP", style="blue")
    convo_table.add_column("Packet Count", style="magenta")

    sorted_edges = sorted(
        G.edges(data=True), key=lambda t: t[2].get("weight", 0), reverse=True
    )
    for u, v, attrs in sorted_edges[:10]:
        convo_table.add_row(u, v, str(attrs["weight"]))
    console.print(convo_table)

    net = Network(height="750px", width="100%", notebook=False, cdn_resources="local")
    net.from_nx(G)
    net.save_graph("communication_map.html")
    console.print(
        "\n[cyan]Interactive communication map saved to 'communication_map.html'[/cyan]"
    )


@traffic_analyzer_app.command(
    name="analyze", help="Analyze a network traffic capture file."
)
def analyze_traffic(
    capture_file: str = typer.Argument(
        ..., help="Path to the network capture file (.pcap or .pcapng)."
    ),
    carve_files: bool = typer.Option(
        False,
        "--carve-files",
        "-c",
        help="Attempt to carve files from unencrypted traffic.",
    ),
):
    """
    Analyzes raw network traffic captures to extract files, identify protocols,
    and map communication channels.
    """
    console.print(f"Analyzing network traffic from: {capture_file}")

    if not os.path.exists(capture_file):
        console.print(f"Error: Capture file not found at '{capture_file}'")
        raise typer.Exit(code=1)
    analyze_protocols(capture_file)

    if carve_files:
        output_dir = "carved_files_output"
        console.print(f"\nCarving files to directory: {output_dir}")
        try:
            carve_files_from_pcap(capture_file, output_dir)
        except Exception as e:
            console.print(f"An error occurred during file carving: {e}")
            raise typer.Exit(code=1)
    console.print("\nTraffic analysis complete.")


if __name__ == "__main__":
    traffic_analyzer_app()
