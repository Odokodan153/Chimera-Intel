import typer
from typing import Optional
from .graph_db import build_and_save_graph
from .ai_core import generate_narrative_from_graph
from .config_loader import API_KEYS
from .utils import console
from rich.markdown import Markdown
from pyvis.network import Network
import json

graph_app = typer.Typer()


@graph_app.command("build")
def build_graph_command(
    target: str = typer.Argument(
        ..., help="The path to the JSON file containing the data for the graph."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the graph to an HTML file."
    ),
):
    """Builds and saves an entity relationship graph for a target."""
    console.print(
        f"[bold cyan]Building entity graph from file '{target}'...[/bold cyan]"
    )

    try:
        with open(target, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        console.print(
            f"[bold red]Error:[/bold red] Input file not found at '{target}'."
        )
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        console.print(
            f"[bold red]Error:[/bold red] Invalid JSON format in file '{target}'."
        )
        raise typer.Exit(code=1)
    # Corrected function call: passes loaded 'data' and 'output_file'

    graph_result = build_and_save_graph(data, output_file)

    if graph_result.error:
        console.print(
            f"[bold red]Error building graph:[/bold red] {graph_result.error}"
        )
        raise typer.Exit(code=1)
    console.print(
        f"[bold green]Successfully built graph with {graph_result.total_nodes} nodes and {graph_result.total_edges} edges.[/bold green]"
    )

    if output_file:
        net = Network(height="800px", width="100%", notebook=True)
        for node in graph_result.nodes:
            net.add_node(node.id, label=node.label, title=node.node_type)
        for edge in graph_result.edges:
            net.add_edge(edge.source, edge.target, title=edge.label)
        net.show(output_file)
        console.print(f"[cyan]Visualization saved to {output_file}[/cyan]")


@graph_app.command("narrate")
def narrate_graph_command(
    target: str = typer.Argument(
        ..., help="The target whose graph you want to narrate."
    ),
):
    """Generates an AI-powered narrative from a target's entity graph."""
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not found.")
        raise typer.Exit(code=1)
    console.print(
        f"[bold cyan]Generating narrative for {target}'s graph...[/bold cyan]"
    )
    narrative_result = generate_narrative_from_graph(target, api_key)

    if narrative_result.error:
        console.print(
            f"[bold red]Error generating narrative:[/bold red] {narrative_result.error}"
        )
        raise typer.Exit(code=1)
    console.print(Markdown(narrative_result.narrative_text))
