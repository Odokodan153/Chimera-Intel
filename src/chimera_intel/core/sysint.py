import logging
import json
from typing import List, Dict, Any
import networkx as nx
import community as community_louvain
import typer
from rich.console import Console
from rich.table import Table
from .schemas import OTAsset, MacroIndicators, SYSINTAnalysisResult, EmergentProperty

logger = logging.getLogger(__name__)


def model_complex_system(intel_sources: Dict[str, List[Any]]) -> nx.MultiDiGraph:
    """Models a complex system using a multi-layered, directed graph."""
    G: nx.MultiDiGraph = nx.MultiDiGraph()  # FIX 1: Added type annotation

    for source_name, items in intel_sources.items():
        for item in items:
            # Safely handle potential key conflicts from .dict()

            data = item.dict()
            node_id = None

            if isinstance(item, OTAsset):
                node_id = item.device_id
                data.pop("type", None)
                data.pop("layer", None)
                G.add_node(node_id, layer="Cyber-Physical", type="OT Asset", **data)
            elif isinstance(item, MacroIndicators):
                node_id = item.country
                data.pop("type", None)
                data.pop("layer", None)
                G.add_node(node_id, layer="Economic", type="Country Macro", **data)
    # 2. Corrected loop for creating relationships

    for country_node, country_data in G.nodes(data=True):
        if country_data.get("type") == "Country Macro":
            for asset_node, asset_data in G.nodes(data=True):
                if asset_data.get("type") == "OT Asset":
                    if country_node in asset_data.get("location", ""):
                        G.add_edge(
                            country_node,
                            asset_node,
                            key="economic_dependency",
                            relationship="supports",
                        )
    return G


def analyze_for_emergent_properties(graph: nx.MultiDiGraph) -> SYSINTAnalysisResult:
    """Analyzes a complex system for emergent properties."""
    if graph.number_of_nodes() == 0:
        return SYSINTAnalysisResult(error="The graph is empty and cannot be analyzed.")
    try:
        emergent_properties = []
        undirected_graph = graph.to_undirected()

        # Deeper analysis of emergent properties
        # Analysis 1: Communities

        partition = community_louvain.best_partition(undirected_graph)
        communities: Dict[int, List[str]] = {}
        for node, community_id in partition.items():
            communities.setdefault(community_id, []).append(node)
        for cid, nodes in communities.items():
            if len(nodes) > 2:
                emergent_properties.append(
                    EmergentProperty(
                        property_type="Influential Community",
                        nodes=nodes,
                        description=f"A tightly interconnected community of {len(nodes)} nodes, suggesting strong mutual influence.",
                    )
                )
        # Analysis 2: Bridge Nodes
        # Calculate centrality without k on smaller graphs for precision

        centrality = nx.betweenness_centrality(graph)
        # Better check for non-zero centrality

        if any(v > 0 for v in centrality.values()):
            # FIX 2: Use lambda function for explicit key access

            bridge_nodes = sorted(
                centrality, key=lambda node: centrality[node], reverse=True
            )[:3]
            emergent_properties.append(
                EmergentProperty(
                    property_type="Critical Bridge Node",
                    nodes=bridge_nodes,
                    description="Nodes that connect different clusters and are critical for the flow of information or resources.",
                )
            )
        # Analysis 3: Cascading Failure Points (Articulation Points)
        # Convert to a simple Graph to use articulation_points

        undirected_simple = nx.Graph(undirected_graph)
        articulation_points = list(nx.articulation_points(undirected_simple))
        if articulation_points:
            emergent_properties.append(
                EmergentProperty(
                    property_type="Cascading Failure Point",
                    nodes=articulation_points,
                    description="The removal of these nodes would split the system into disconnected components.",
                )
            )
        # Provide feedback if no properties are found

        if not emergent_properties:
            emergent_properties.append(
                EmergentProperty(
                    property_type="No Emergent Properties Detected",
                    nodes=[],
                    description="The system did not exhibit any detectable emergent phenomena based on current data.",
                )
            )
        return SYSINTAnalysisResult(emergent_properties=emergent_properties)
    except Exception as e:
        logger.error(f"Failed to analyze system graph: {e}")
        return SYSINTAnalysisResult(error=str(e))


app = typer.Typer(
    name="sysint",
    help="Systemic Intelligence (SYSINT) & Cascade Analyzer.",
    no_args_is_help=True,
)


@app.command("analyze")
def run_sysint_analysis(
    project_file: str = typer.Option(
        ..., help="Path to a JSON project file containing all intelligence data."
    )
):
    """Models and analyzes a complex systemic environment from a project file."""
    console = Console()

    # 4. FIXED: Load data from a file for realistic analysis

    try:
        with open(project_file, "r", encoding="utf-8") as f:
            project_data = json.load(f)
        # FIX 3: Explicitly type the intel_sources dictionary to satisfy mypy

        intel_sources: Dict[str, List[Any]] = {
            "cyber": [OTAsset(**item) for item in project_data.get("cyber", [])],
            "economic": [
                MacroIndicators(**item) for item in project_data.get("economic", [])
            ],
        }
    except Exception as e:
        console.print(f"[bold red]Error loading project file:[/] {e}")
        return
    with console.status(
        "[bold green]Modeling and analyzing the systemic environment...[/]"
    ):
        graph = model_complex_system(intel_sources)
        result = analyze_for_emergent_properties(graph)
    if result.error:
        console.print(f"[bold red]Error:[/] {result.error}")
        return
    console.print("[bold green]Systemic Intelligence Analysis Complete[/]")
    console.print(
        f"Analyzed {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges."
    )

    prop_table = Table(title="Identified Emergent Properties")
    prop_table.add_column("Property Type", style="cyan")
    prop_table.add_column("Description", style="magenta")
    prop_table.add_column("Involved Nodes", style="yellow")

    for prop in result.emergent_properties:
        prop_table.add_row(prop.property_type, prop.description, ", ".join(prop.nodes))
    console.print(prop_table)
