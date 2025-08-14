import typer
import json
from rich.console import Console
from rich.panel import Panel
from pyvis.network import Network
import os
from typing import Dict, Any

# --- CORRECTED Absolute Imports ---
from .config_loader import CONFIG
from .utils import console

def generate_knowledge_graph(json_data: Dict[str, Any], output_path: str) -> None:
    """
    Generates an interactive HTML knowledge graph from a JSON scan result.

    This function uses the pyvis library to build a network graph. It parses the
    input JSON data, creating nodes for the main target, subdomains, IP addresses,
    and technologies, and then connects them with edges. The final graph is

    Args:
        json_data (Dict[str, Any]): The loaded JSON data from a scan.
        output_path (str): The path to save the generated HTML file.
    """
    try:
        net = Network(height="900px", width="100%", bgcolor="#222222", font_color="white", notebook=False, directed=True)

        # --- Central Node (The Target) ---
        target = json_data.get('domain') or json_data.get('company', 'Unknown Target')
        net.add_node(target, label=target, color="#ff4757", size=30, shape="dot", title="Main Target")

        # --- Footprint Module Data ---
        footprint_data = json_data.get('footprint', {})
        for sub_item in footprint_data.get('subdomains', {}).get('results', []):
            subdomain = sub_item.get('domain')
            if subdomain:
                net.add_node(subdomain, label=subdomain, color="#1e90ff", size=15, shape="dot", title="Subdomain")
                net.add_edge(target, subdomain)
        for ip in footprint_data.get('dns_records', {}).get('A', []):
            if "Error" not in str(ip):
                net.add_node(ip, label=ip, color="#feca57", size=20, shape="triangle", title="IP Address")
                net.add_edge(target, ip)

        # --- Web Analyzer Module Data ---
        web_data = json_data.get('web_analysis', {})
        for tech_item in web_data.get('tech_stack', {}).get('results', []):
            tech = tech_item.get('technology')
            if tech:
                net.add_node(tech, label=tech, color="#576574", size=12, shape="square", title="Technology")
                net.add_edge(target, tech)
        
        # --- CHANGE: Access the config via attributes instead of dictionary keys ---
        # This part of the config is not yet modeled in Pydantic, so we access it as a dict.
        # A future improvement would be to model 'reporting' in schemas.py as well.
        physics_options = CONFIG.model_dump().get("reporting", {}).get("graph", {}).get("physics_options", "")
        if physics_options:
            net.set_options(physics_options)

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
    output_file: str = typer.Option(None, "--output", "-o", help="Path to save the HTML graph. Defaults to '<target>_graph.html'.")
):
    """
    Creates an interactive knowledge graph from a saved JSON scan file.
    """
    console.print(Panel(f"[bold green]Generating Knowledge Graph from:[/] {json_file}", title="Chimera Intel | Grapher", border_style="green"))

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error reading file:[/] {e}")
        raise typer.Exit(code=1)

    if not output_file:
        target_name = data.get('domain') or data.get('company', 'graph')
        output_path = f"{target_name.replace('.', '_')}_graph.html"
    else:
        output_path = output_file

    generate_knowledge_graph(data, output_path)