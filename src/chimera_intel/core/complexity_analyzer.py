"""
Module for Systemic Risk and Complexity Analysis.

Applies System Dynamics principles to map interdependencies between
discovered entities (assets, companies, people) to predict
cascading effects (Systemic Risk).
"""

import typer
import logging
import networkx as nx
from typing import Optional, List
from .schemas import ComplexityAnalysisResult, SystemicRiskVector
from .utils import save_or_print_results, console
from .database import get_aggregated_data_for_target, save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)

complexity_analyzer_app = typer.Typer()


def build_system_graph(target: str) -> nx.Graph:
    """
    Builds a simple graph of all known entities related to the target
    from the project database.
    
    This is a simplified example. A real one would pull from many
    data sources (scans, connections, etc.).
    """
    G = nx.Graph()
    
    # 1. Add the primary target
    G.add_node(target, type="target_company")
    
    # 2. Get aggregated data
    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data:
        return G
        
    modules = aggregated_data.get("modules", {})
    
    # 3. Add personnel as nodes
    personnel = modules.get("personnel_osint_emails", {}).get("employee_profiles", [])
    for person in personnel:
        email = person.get("email", "unknown")
        G.add_node(email, type="personnel")
        G.add_edge(target, email, relationship="employs")
        
    # 4. Add domains as nodes
    domains = modules.get("footprint_subdomains", {}).get("subdomains", [])
    for domain in domains:
        G.add_node(domain, type="domain")
        G.add_edge(target, domain, relationship="owns")

    # 5. Add supply chain data
    shipments = modules.get("corporate_supplychain", {}).get("shipments", [])
    for ship in shipments:
        shipper = ship.get("shipper")
        if shipper and shipper != target:
            G.add_node(shipper, type="supplier")
            G.add_edge(target, shipper, relationship="supplied_by")

    return G


def analyze_systemic_risk(target: str, graph: nx.Graph) -> ComplexityAnalysisResult:
    """
    Analyzes the system graph for critical nodes and cascading failure points.
    """
    if graph.number_of_nodes() == 0:
        return ComplexityAnalysisResult(
            target=target, error="No system graph could be built."
        )

    risks: List[SystemicRiskVector] = []

    # 1. Find Central Nodes (High-Impact Points)
    # Using degree centrality for simplicity
    try:
        centrality = nx.degree_centrality(graph)
        critical_nodes = sorted(centrality, key=centrality.get, reverse=True)[:5]
        
        risks.append(
            SystemicRiskVector(
                risk_type="High-Centrality Node",
                description="These nodes are the most connected. Their compromise would have the widest immediate impact.",
                affected_nodes=critical_nodes,
                impact_score=0.8
            )
        )

        # 2. Find Choke Points (Articulation Points / Bridges)
        articulation_points = list(nx.articulation_points(graph))
        if articulation_points:
            risks.append(
                SystemicRiskVector(
                    risk_type="Cascading Failure Point",
                    description="These nodes (articulation points) connect different parts of the system. Their removal would split the network.",
                    affected_nodes=articulation_points,
                    impact_score=1.0
                )
            )

    except Exception as e:
        logger.error(f"Error during graph analysis: {e}")
        return ComplexityAnalysisResult(target=target, error=f"Graph analysis failed: {e}")

    summary = f"System built with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges. "
    summary += f"Found {len(articulation_points)} critical failure point(s) and {len(critical_nodes)} highly central nodes."

    return ComplexityAnalysisResult(
        target=target,
        system_summary=summary,
        systemic_risks=risks,
        node_count=graph.number_of_nodes(),
        edge_count=graph.number_of_edges(),
    )


@complexity_analyzer_app.command("run")
def run_complexity_analysis(
    target: Optional[str] = typer.Argument(
        None, help="The target to analyze. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Maps system interdependencies and predicts cascading failure points.
    """
    target_name = resolve_target(target)
    
    with console.status(
        f"[bold cyan]Building system graph for {target_name}...[/bold cyan]"
    ):
        system_graph = build_system_graph(target_name)
    
    with console.status(
        f"[bold cyan]Analyzing systemic risk for {target_name}...[/bold cyan]"
    ):
        results_model = analyze_systemic_risk(target_name, system_graph)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="complexity_analysis", data=results_dict
    )