import typer
import json
from pyvis.network import Network  # type: ignore
import os
from typing import Dict, Any
import logging
from .config_loader import CONFIG
from .utils import console
from .graph_schemas import Node, Edge, EntityGraphResult

# Get a logger instance for this specific file

logger = logging.getLogger(__name__)


def build_and_save_graph(
    json_data: Dict[str, Any], output_path: str
) -> EntityGraphResult:
    """Builds and saves an interactive HTML knowledge graph from a JSON scan result.

    This function uses the pyvis library to build a network graph. It parses the
    input JSON data, creating nodes for the main target, subdomains, IP addresses,
    and technologies, and then connects them with edges. The final graph is
    configured with physics options from the config.yaml file for an interactive layout.

    Args:
        json_data (Dict[str, Any]): The loaded JSON data from a scan.
        output_path (str): The path to save the generated HTML file.

    Returns:
        EntityGraphResult: A Pydantic model containing the graph data.
    """
    nodes = []
    edges = []
    try:
        net = Network(
            height="900px",
            width="100%",
            bgcolor="#222222",
            font_color="white",
            notebook=False,
            directed=True,
        )

        target = json_data.get("domain") or json_data.get("company", "Unknown Target")
        net.add_node(
            target,
            label=target,
            color="#ff4757",
            size=30,
            shape="dot",
            title="Main Target",
        )
        nodes.append(
            Node(id=target, label=target, node_type="Main Target", properties={})
        )

        footprint_data = json_data.get("footprint", {})
        for sub_item in footprint_data.get("subdomains", {}).get("results", []):
            subdomain = sub_item.get("domain")
            if subdomain:
                net.add_node(
                    subdomain,
                    label=subdomain,
                    color="#1e90ff",
                    size=15,
                    shape="dot",
                    title="Subdomain",
                )
                net.add_edge(target, subdomain)
                nodes.append(
                    Node(
                        id=subdomain,
                        label=subdomain,
                        node_type="Subdomain",
                        properties={},
                    )
                )
                edges.append(
                    Edge(
                        source=target,
                        target=subdomain,
                        label="has_subdomain",
                        properties={},
                    )
                )
        for ip in footprint_data.get("dns_records", {}).get("A", []):
            if "Error" not in str(ip):
                net.add_node(
                    ip,
                    label=ip,
                    color="#feca57",
                    size=20,
                    shape="triangle",
                    title="IP Address",
                )
                net.add_edge(target, ip)
                nodes.append(
                    Node(id=ip, label=ip, node_type="IP Address", properties={})
                )
                edges.append(
                    Edge(source=target, target=ip, label="resolves_to", properties={})
                )
        web_data = json_data.get("web_analysis", {})
        for tech_item in web_data.get("tech_stack", {}).get("results", []):
            tech = tech_item.get("technology")
            if tech:
                net.add_node(
                    tech,
                    label=tech,
                    color="#576574",
                    size=12,
                    shape="square",
                    title="Technology",
                )
                net.add_edge(target, tech)
                nodes.append(
                    Node(id=tech, label=tech, node_type="Technology", properties={})
                )
                edges.append(
                    Edge(source=target, target=tech, label="uses_tech", properties={})
                )
        # Apply physics options from config.yaml

        physics_options = (
            CONFIG.model_dump()
            .get("reporting", {})
            .get("graph", {})
            .get("physics_options", "")
        )
        if physics_options:
            net.set_options(physics_options)
        net.save_graph(output_path)
        logger.info(
            "Successfully generated interactive graph at: %s",
            os.path.abspath(output_path),
        )
        console.print("   [dim]Open this HTML file in your browser to explore.[/dim]")
        return EntityGraphResult(
            target=target,
            total_nodes=len(nodes),
            total_edges=len(edges),
            nodes=nodes,
            edges=edges,
        )
    except Exception as e:
        logger.error("An error occurred during graph generation: %s", e)
        return EntityGraphResult(
            target="", total_nodes=0, total_edges=0, nodes=[], edges=[], error=str(e)
        )


# --- Typer CLI Application ---


graph_app = typer.Typer()


@graph_app.command("create")
def create_knowledge_graph(
    json_file: str = typer.Argument(..., help="Path to the JSON scan result file."),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Path to save the HTML graph."
    ),
):
    """Creates an interactive knowledge graph from a saved JSON scan file."""
    logger.info("Generating knowledge graph from: %s", json_file)

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error("Error reading file '%s' for graph generation: %s", json_file, e)
        raise typer.Exit(code=1)
    if not output_file:
        target_name = data.get("domain") or data.get("company", "graph")
        output_path = f"{target_name.replace('.', '_')}_graph.html"
    else:
        output_path = output_file
    build_and_save_graph(data, output_path)
