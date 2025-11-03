import typer
import json
from pyvis.network import Network  # type: ignore
import os
import uuid
from datetime import datetime
from chimera_intel.core.schemas import FootprintResult, PersonnelOSINTResult
from typing import Dict, Any, List, Optional
import logging
from .config_loader import CONFIG
from .utils import console
from .graph_schemas import GraphNode, GraphEdge, EntityGraphResult  # Corrected imports
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
        self, query: str, parameters: Optional[Dict[str, Any]] = None  # Added Optional
    ) -> List[Dict[str, Any]]:
        """
        Executes a Cypher query against the database.
        """
        if not self._driver:
            logger.error("Cannot execute query: database driver is not available.")
            return []
        try:
            with self._driver.session() as session:
                parameters = parameters or {}  # Handle optional None
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

# Corrected configuration access to match the schema definition


graph_db_instance = GraphDatabase(
    uri=CONFIG.graph_db.uri,
    user=CONFIG.graph_db.username,
    password=CONFIG.graph_db.password,
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
            GraphNode(
                id=target, label=target, node_type="Main Target", properties={}
            )  # Corrected Node to GraphNode
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
                    GraphNode(  # Corrected Node to GraphNode
                        id=subdomain,
                        label=subdomain,
                        node_type="Subdomain",
                        properties={},
                    )
                )
                edges.append(
                    GraphEdge(  # Corrected Edge to GraphEdge
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
                    GraphNode(
                        id=ip, label=ip, node_type="IP Address", properties={}
                    )  # Corrected Node to GraphNode
                )
                edges.append(
                    GraphEdge(
                        source=target, target=ip, label="resolves_to", properties={}
                    )  # Corrected Edge to GraphEdge
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
                    GraphNode(
                        id=tech, label=tech, node_type="Technology", properties={}
                    )  # Corrected Node to GraphNode
                )
                edges.append(
                    GraphEdge(
                        source=target, target=tech, label="uses_tech", properties={}
                    )  # Corrected Edge to GraphEdge
                )
        # Apply physics options from config.yaml

        # Corrected access for the 'graph' dictionary

        physics_options = None
        if CONFIG.reporting and CONFIG.reporting.graph:
            physics_options = CONFIG.reporting.graph.physics_options
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

def add_graph_node(tx, label: str, properties: Dict[str, Any], primary_key: str = "id"):
    """
    Idempotently creates or merges a node in the graph.
    
    Args:
        tx: The Neo4j transaction.
        label: The label for the node (e.g., "Domain", "IP").
        properties: A dictionary of properties for the node.
        primary_key: The property key to merge on (default: "id").
    """
    prop_key = properties.get(primary_key)
    if not prop_key:
        logger.warning(f"Node of type {label} missing primary key '{primary_key}'. Skipping.")
        return

    query = f"""
    MERGE (n:{label} {{{primary_key}: $prop_key}})
    ON CREATE SET n = $properties
    ON MATCH SET n += $properties
    """
    tx.run(query, prop_key=prop_key, properties=properties)

def add_graph_relationship(tx, source_label: str, source_id: str, 
                         target_label: str, target_id: str, 
                         relationship_type: str, 
                         source_key: str = "id", target_key: str = "id"):
    """
    Creates a relationship between two existing nodes.
    
    Args:
        tx: The Neo4j transaction.
        source_label: The label of the source node.
        source_id: The primary key value of the source node.
        target_label: The label of the target node.
        target_id: The primary key value of the target node.
        relationship_type: The type of relationship (e.g., "RESOLVES_TO").
        source_key: The property key of the source node (default: "id").
        target_key: The property key of the target node (default: "id").
    """
    query = f"""
    MATCH (a:{source_label} {{{source_key}: $source_id}})
    MATCH (b:{target_label} {{{target_key}: $target_id}})
    MERGE (a)-[r:{relationship_type}]->(b)
    """
    tx.run(query, source_id=source_id, target_id=target_id)

def process_footprint_for_graph(scan_result: FootprintResult):
    """
    Processes a FootprintResult and adds the entities to the Neo4j graph.
    This demonstrates the domain <-> IP <-> cert correlation.
    """
    if not graph_db_instance or not graph_db_instance._driver:
        logger.warning("Graph DB not connected. Skipping graph processing.")
        return

    domain = scan_result.domain
    
    with graph_db_instance._driver.session() as session:
        # Add the main domain
        session.write_transaction(
            add_graph_node, "Domain", {"id": domain, "name": domain}, "id"
        )
        
        # Add DNS A records (Domain -> IP)
        if scan_result.footprint.dns_records.get("A"):
            for ip in scan_result.footprint.dns_records["A"]:
                session.write_transaction(
                    add_graph_node, "IP", {"id": ip, "address": ip}, "id"
                )
                session.write_transaction(
                    add_graph_relationship, "Domain", domain, "IP", ip, "RESOLVES_TO"
                )

        # Add Subdomains (Domain -> Subdomain)
        if scan_result.footprint.subdomains:
            for sub in scan_result.footprint.subdomains.results:
                if sub.domain:
                    session.write_transaction(
                        add_graph_node, "Domain", {"id": sub.domain, "name": sub.domain, "is_subdomain": True}, "id"
                    )
                    session.write_transaction(
                        add_graph_relationship, "Domain", domain, "Domain", sub.domain, "HAS_SUBDOMAIN"
                    )

        # Add TLS Cert (Domain -> Certificate)
        if scan_result.footprint.tls_cert_info:
            cert_subject = scan_result.footprint.tls_cert_info.subject
            if cert_subject:
                cert_id = cert_subject + "_" + scan_result.footprint.tls_cert_info.not_after
                cert_props = scan_result.footprint.tls_cert_info.model_dump()
                cert_props["id"] = cert_id
                
                session.write_transaction(
                    add_graph_node, "Certificate", cert_props, "id"
                )
                session.write_transaction(
                    add_graph_relationship, "Domain", domain, "Certificate", cert_id, "HAS_CERT"
                )

def process_personnel_for_graph(scan_result: PersonnelOSINTResult):
    """
    Processes a PersonnelOSINTResult to link Company <-> Person.
    """
    if not graph_db_instance or not graph_db_instance._driver:
        logger.warning("Graph DB not connected. Skipping graph processing.")
        return

    company_name = scan_result.organization_name or scan_result.domain
    
    with graph_db_instance._driver.session() as session:
        # Add the company
        session.write_transaction(
            add_graph_node, "Company", {"id": company_name, "name": company_name}, "id"
        )
        
        # Add employees (Company -> Person)
        for emp in scan_result.employee_profiles:
            person_props = emp.model_dump()
            person_props["id"] = emp.email
            session.write_transaction(
                add_graph_node, "Person", person_props, "id"
            )
            session.write_transaction(
                add_graph_relationship, "Company", company_name, "Person", emp.email, "EMPLOYS"
            )

def add_annotation_to_node(node_label: str, node_id: str, user: str, content: str, node_key: str = "id") -> str:
    """
    Adds an Annotation node to the graph and links it to an existing entity.
    This implements Feature 7 (Annotation).
    """
    if not graph_db_instance or not graph_db_instance._driver:
        logger.error("Graph DB not connected. Cannot add annotation.")
        raise typer.Exit(code=1)

    annotation_id = str(uuid.uuid4())
    annotation_props = {
        "id": annotation_id,
        "user": user,
        "content": content,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    with graph_db_instance._driver.session() as session:
        # Add the annotation node
        session.write_transaction(
            add_graph_node, "Annotation", annotation_props, "id"
        )
        # Link annotation to the target node
        session.write_transaction(
            add_graph_relationship, 
            "Annotation", annotation_id,
            node_label, node_id,
            "ANNOTATES",
            "id", node_key
        )
    return annotation_id
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

@graph_app.command("add-annotation")
def cli_add_annotation(
    node_label: str = typer.Argument(..., help="The label of the node (e.g., 'Domain', 'IP')."),
    node_id: str = typer.Argument(..., help="The primary ID of the node (e.g., 'example.com', '1.2.3.4')."),
    content: str = typer.Argument(..., help="The text content of the annotation."),
    user: str = typer.Option("analyst", "--user", "-u", help="The user adding the annotation."),
    node_key: str = typer.Option("id", help="The property key of the node to match on.")
):
    """
    Adds an analyst annotation to an entity in the Neo4j graph.
    """
    try:
        annotation_id = add_annotation_to_node(node_label, node_id, user, content, node_key)
        console.print(f"[bold green]Success:[/bold green] Added annotation {annotation_id} to {node_label} {node_id}.")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Could not add annotation: {e}")
        raise typer.Exit(code=1)
