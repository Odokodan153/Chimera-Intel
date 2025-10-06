"""
Graph Database Module for Chimera Intel.

Handles interactions with the Neo4j graph database, including building,
storing, and querying entity graphs.
"""

from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase
from .config_loader import API_KEYS
from .utils import console
from .schemas import EntityGraphResult, GraphNode, GraphEdge
from .database import get_aggregated_data_for_target


class Neo4jConnection:
    """A class to manage the connection to the Neo4j database."""

    def __init__(self, uri, user, password):
        self.__uri = uri
        self.__user = user
        self.__password = password
        self.__driver = None
        try:
            self.__driver = GraphDatabase.driver(
                self.__uri, auth=(self.__user, self.__password)
            )
        except Exception as e:
            console.print(f"[bold red]Failed to create Neo4j driver:[/bold red] {e}")

    def close(self):
        """Closes the database connection."""
        if self.__driver is not None:
            self.__driver.close()

    def query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
        db: Optional[str] = None,
    ) -> Optional[List[Any]]:
        """Executes a query against the database."""
        assert self.__driver is not None, "Driver not initialized!"
        session = None
        response = None
        try:
            session = (
                self.__driver.session(database=db)
                if db is not None
                else self.__driver.session()
            )
            response = list(session.run(query, parameters))
        except Exception as e:
            console.print(f"[bold red]Query failed:[/bold red] {e}")
            return None
        finally:
            if session is not None:
                session.close()
        return response


def get_graph_db_connection() -> Optional[Neo4jConnection]:
    """Initializes and returns a connection to the Neo4j database."""
    uri = getattr(API_KEYS, "neo4j_uri", None)
    user = getattr(API_KEYS, "neo4j_user", None)
    password = getattr(API_KEYS, "neo4j_password", None)

    if not all([uri, user, password]):
        console.print("[bold red]Neo4j connection details not configured.[/bold red]")
        return None
    return Neo4jConnection(uri, user, password)


def build_entity_graph(target: str) -> EntityGraphResult:
    """
    Builds an entity graph from aggregated scan data for a target.
    """
    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data:
        return EntityGraphResult(
            target=target, total_nodes=0, total_edges=0, error="No data to build graph."
        )
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []

    # Add the central target node

    nodes[target] = GraphNode(id=target, node_type="Domain", label=target)

    # Process modules to add nodes and edges
    # Example: Footprint data

    footprint_data = aggregated_data.get("modules", {}).get("footprint", {})
    if "subdomains" in footprint_data:
        for sub in footprint_data["subdomains"].get("results", []):
            sub_name = sub.get("domain")
            if sub_name:
                nodes[sub_name] = GraphNode(
                    id=sub_name, node_type="Subdomain", label=sub_name
                )
                edges.append(
                    GraphEdge(source=target, target=sub_name, label="HAS_SUBDOMAIN")
                )
    return EntityGraphResult(
        target=target,
        total_nodes=len(nodes),
        total_edges=len(edges),
        nodes=list(nodes.values()),
        edges=edges,
    )


def save_graph_to_neo4j(graph_data: EntityGraphResult):
    """Saves a built entity graph to the Neo4j database."""
    conn = get_graph_db_connection()
    if not conn:
        return
    # Using a transaction to ensure atomicity

    with conn._Neo4jConnection__driver.session() as session:
        session.write_transaction(
            _create_and_link_nodes, graph_data.nodes, graph_data.edges
        )
    conn.close()
    console.print(f"[green]Graph for {graph_data.target} saved to Neo4j.[/green]")


def _create_and_link_nodes(tx, nodes, edges):
    """A private function to handle the transaction logic."""
    for node in nodes:
        tx.run(
            "MERGE (n:%s {id: $id, label: $label}) SET n += $props" % node.node_type,
            id=node.id,
            label=node.label,
            props=node.properties,
        )
    for edge in edges:
        tx.run(
            """
            MATCH (a {id: $source})
            MATCH (b {id: $target})
            MERGE (a)-[r:%s]->(b)
            SET r += $props
        """
            % edge.label,
            source=edge.source,
            target=edge.target,
            props=edge.properties,
        )


def build_and_save_graph(target: str) -> "EntityGraphResult":
    """
    Builds and saves an entity graph for a given target.
    """
    # This is a placeholder for the actual graph building logic

    from .schemas import EntityGraphResult, GraphNode, GraphEdge

    nodes = [GraphNode(id=target, node_type="Domain", label=target)]
    edges = []

    return EntityGraphResult(
        target=target,
        total_nodes=len(nodes),
        total_edges=len(edges),
        nodes=nodes,
        edges=edges,
    )
