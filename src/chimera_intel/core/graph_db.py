import typer
import json
from pyvis.network import Network  # type: ignore
import os
from typing import Dict, Any, List
import logging
from .config_loader import CONFIG
from .utils import console
from .graph_schemas import Node, Edge, EntityGraphResult
from neo4j import GraphDatabase as Neo4jGraphDatabase
from neo4j.exceptions import ServiceUnavailable

logger = logging.getLogger(__name__)

class GraphDatabase:
    """
    Manages the connection to a Neo4j graph database.
    """

    def __init__(self, uri, user, password):
        try:
            self._driver = Neo4jGraphDatabase.driver(uri, auth=(user, password))
            logger.info("Successfully connected to Neo4j database.")
        except ServiceUnavailable as e:
            logger.error("Could not connect to Neo4j database at %s: %s", uri, e)
            self._driver = None

    def execute_query(
        self, query: str, parameters: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Executes a Cypher query against the database.
        """
        if not self._driver:
            logger.error("Cannot execute query: database driver is not available.")
            return []
        try:
            with self._driver.session() as session:
                result = session.run(query, parameters)
                return [record.data() for record in result]
        except Exception as e:
            logger.error("An error occurred while executing the query: %s", e)
            return []

    def close(self):
        if self._driver:
            self._driver.close()
            logger.info("Neo4j database connection closed.")


# --- Singleton instance of the graph database connection ---
# The CLI will import and use this instance to run queries.
# Connection details are populated from the config.

graph_db_instance = GraphDatabase(
    uri=CONFIG.get("graph_db", {}).get("uri", "bolt://localhost:7687"),
    user=CONFIG.get("graph_db", {}).get("user", "neo4j"),
    password=CONFIG.get("graph_db", {}).get("password", "password"),
)


def build_and_save_graph(
    json_data: Dict[str, Any], output_path: str
) -> EntityGraphResult:
    """Builds and saves an interactive HTML knowledge graph from a JSON scan result."""
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
