import logging
from typing import List, Tuple
import networkx as nx
import typer
from rich.console import Console
from rich.table import Table
import json

# Assuming the following data structures from other modules

from .schemas import (
    CPSAnalysisResult,
    CascadingFailurePath,
    OTAsset,
    GeoLocation,
    SignalIntercept,
    Vulnerability,
)

logger = logging.getLogger(__name__)


def model_cyber_physical_system(
    ot_assets: List[OTAsset],
    geo_locations: List[GeoLocation],
    signal_intercepts: List[SignalIntercept],
    vulnerabilities: List[Vulnerability],
) -> nx.Graph:
    """Models a cyber-physical system as a graph."""
    G: nx.Graph = nx.Graph()

    # Add nodes for each component

    for asset in ot_assets:
        G.add_node(asset.device_id, node_type="OT Asset", attributes=asset.dict())
    for loc in geo_locations:
        G.add_node(loc.name, node_type="Location", attributes=loc.dict())
    for sig in signal_intercepts:
        G.add_node(sig.signal_id, node_type="Signal", attributes=sig.dict())
    for vuln in vulnerabilities:
        G.add_node(vuln.cve, node_type="Vulnerability", attributes=vuln.dict())
    # Create edges based on relationships

    for asset in ot_assets:
        if asset.location and G.has_node(asset.location):
            G.add_edge(asset.device_id, asset.location, relationship="located_at")
        for v in asset.vulnerabilities:
            if G.has_node(v):
                G.add_edge(asset.device_id, v, relationship="is_vulnerable_to")
    return G


def analyze_cps_for_cascading_failures(
    graph: nx.Graph,
) -> Tuple[CPSAnalysisResult, nx.Graph]:
    """
    Analyzes a cyber-physical system graph, returning the result and the graph separately.
    """
    try:
        # Identify critical nodes using betweenness centrality

        centrality = nx.betweenness_centrality(graph)
        critical_nodes = sorted(
            centrality, key=lambda node_id: centrality[node_id], reverse=True
        )[:5]

        # Identify potential cascading failure paths

        failure_paths = []
        for i, start_node in enumerate(critical_nodes):
            for end_node in critical_nodes[i + 1 :]:
                if nx.has_path(graph, start_node, end_node):
                    for path in nx.all_simple_paths(
                        graph, source=start_node, target=end_node, cutoff=5
                    ):
                        failure_paths.append(
                            CascadingFailurePath(
                                path=path,
                                description=f"A failure at {start_node} could potentially cascade to {end_node}.",
                            )
                        )
        result = CPSAnalysisResult(
            critical_nodes=critical_nodes,
            failure_paths=failure_paths,
        )
        return result, graph
    except Exception as e:
        logger.error(f"Failed to analyze CPS graph: {e}")
        result = CPSAnalysisResult(error=str(e))
        return result, graph


app = typer.Typer(
    name="cpint",
    help="Integrated Cyber-Physical Systems Intelligence.",
    no_args_is_help=True,
)


@app.command("analyze")
def run_cps_analysis(
    project_file: str = typer.Option(
        ..., help="Path to a JSON project file with all intelligence data."
    ),
):
    """
    Models and analyzes a cyber-physical system from project data.
    """
    console = Console()
    try:
        with open(project_file, "r") as f:
            data = json.load(f)
        ot_assets = [OTAsset(**a) for a in data.get("ot_assets", [])]
        geo_locations = [GeoLocation(**g) for g in data.get("geo_locations", [])]
        signal_intercepts = [
            SignalIntercept(**s) for s in data.get("signal_intercepts", [])
        ]
        vulnerabilities = [Vulnerability(**v) for v in data.get("vulnerabilities", [])]
    except Exception as e:
        console.print(f"[bold red]Error loading project file:[/] {e}")
        return
    with console.status(
        "[bold green]Modeling and analyzing the cyber-physical system...[/]"
    ):
        graph = model_cyber_physical_system(
            ot_assets, geo_locations, signal_intercepts, vulnerabilities
        )
        result, system_model = analyze_cps_for_cascading_failures(graph)
    if result.error:
        console.print(f"[bold red]Error:[/] {result.error}")
        return
    console.print("[bold green]Cyber-Physical System Analysis Complete[/]")

    table = Table(title="Critical System Nodes")
    table.add_column("Node ID", style="cyan")
    table.add_column("Node Type", style="magenta")
    for node_id in result.critical_nodes:
        table.add_row(node_id, system_model.nodes[node_id].get("node_type", "N/A"))
    console.print(table)

    path_table = Table(title="Potential Cascading Failure Paths")
    path_table.add_column("Path", style="yellow")
    path_table.add_column("Description", style="red")
    for path in result.failure_paths:
        path_table.add_row(" -> ".join(path.path), path.description)
    console.print(path_table)
