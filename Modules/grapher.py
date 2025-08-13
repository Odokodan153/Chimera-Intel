import typer
import json
from rich.console import Console
from rich.panel import Panel
from pyvis.network import Network
import os

console = Console()

def generate_knowledge_graph(json_data: dict, output_path: str):
    """
    Generates an interactive HTML knowledge graph from a JSON scan result.

    Args:
        json_data (dict): The loaded JSON data from a scan.
        output_path (str): The path to save the generated HTML file.
    """
    try:
        # Initialize the Pyvis network graph
        net = Network(height="800px", width="100%", bgcolor="#222222", font_color="white", notebook=False, directed=True)

        # --- Central Node (The Target) ---
        target = json_data.get('domain') or json_data.get('company', 'Unknown Target')
        net.add_node(target, label=target, color="#ff4757", size=30, shape="dot", title="Main Target")

        # --- Footprint Module Data ---
        if 'footprint' in json_data:
            footprint_data = json_data['footprint']
            # Add subdomains as nodes
            if 'subdomains' in footprint_data and 'results' in footprint_data['subdomains']:
                for sub_item in footprint_data['subdomains']['results']:
                    subdomain = sub_item.get('domain')
                    if subdomain:
                        net.add_node(subdomain, label=subdomain, color="#1e90ff", size=15, shape="dot", title="Subdomain")
                        net.add_edge(target, subdomain)
            # Add IP addresses from DNS A records
            if 'dns_records' in footprint_data and 'A' in footprint_data['dns_records']:
                for ip in footprint_data['dns_records']['A']:
                    if "Error" not in ip:
                        net.add_node(ip, label=ip, color="#feca57", size=20, shape="triangle", title="IP Address")
                        net.add_edge(target, ip)

        # --- Web Analyzer Module Data ---
        if 'web_analysis' in json_data:
            web_data = json_data['web_analysis']
            # Add technologies as nodes
            if 'tech_stack' in web_data and 'results' in web_data['tech_stack']:
                for tech_item in web_data['tech_stack']['results']:
                    tech = tech_item.get('technology')
                    if tech:
                        net.add_node(tech, label=tech, color="#576574", size=12, shape="square", title="Technology")
                        net.add_edge(target, tech)
        
        # Configure physics for a better layout
        net.set_options("""
        var options = {
          "physics": {
            "barnesHut": {
              "gravitationalConstant": -30000,
              "centralGravity": 0.3,
              "springLength": 150
            },
            "minVelocity": 0.75
          }
        }
        """)

        # Generate the HTML file
        net.save_graph(output_path)
        console.print(f"[bold green]Successfully generated interactive graph at:[/] {os.path.abspath(output_path)}")
        console.print("   [dim]Open this HTML file in your browser to explore.[/dim]")

    except Exception as e:
        console.print(f"[bold red]Graph Generation Error:[/bold red] {e}")


# --- Typer CLI Application ---

graph_app = typer.Typer()

@graph_app.command("create")
def create_knowledge_graph(
    json_file: str = typer.Argument(..., help="Path to the JSON scan result file."),
    output_file: str = typer.Option(None, "--output", "-o", help="Path to save the HTML graph. Defaults to '<target>.html'.")
):
    """
    Creates an interactive knowledge graph from a saved JSON scan file.
    """
    console.print(Panel(f"[bold green]Generating Knowledge Graph from:[/] {json_file}", title="Chimera Intel | Grapher", border_style="green"))

    # Load the JSON data
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] Input file not found at '{json_file}'")
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        console.print(f"[bold red]Error:[/] Invalid JSON in file '{json_file}'")
        raise typer.Exit(code=1)

    # Determine the output path
    if not output_file:
        target_name = data.get('domain') or data.get('company', 'graph')
        output_path = f"{target_name.replace('.', '_')}_graph.html"
    else:
        output_path = output_file

    # Generate the graph
    generate_knowledge_graph(data, output_path)