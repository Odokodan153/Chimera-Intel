import sqlite3
import json
from .database import get_all_scans_for_target
from .graph_schemas import GraphNode, GraphEdge, EntityGraphResult

DB_FILE = "chimera_intel.db"


def build_and_save_graph(target: str) -> EntityGraphResult:
    """Builds and saves an entity relationship graph for a target."""
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    scans = get_all_scans_for_target(target)
    if not scans:
        return EntityGraphResult(
            target=target,
            total_nodes=0,
            total_edges=0,
            error="No scans found for target.",
        )
    # Add the central target node

    nodes[target] = GraphNode(id=target, node_type="Target", label=target)

    for scan in scans:
        module = scan["module"]
        data = json.loads(scan["scan_data"])

        if module == "footprint":
            # Extract IPs and subdomains

            ips = data.get("footprint", {}).get("dns_records", {}).get("A", [])
            for ip in ips:
                nodes[ip] = GraphNode(id=ip, node_type="IPAddress", label=ip)
                edges.append(GraphEdge(source=target, target=ip, label="HAS_IP"))
            subdomains = (
                data.get("footprint", {}).get("subdomains", {}).get("results", [])
            )
            for sub in subdomains:
                subdomain = sub.get("domain")
                if subdomain:
                    nodes[subdomain] = GraphNode(
                        id=subdomain, node_type="Domain", label=subdomain
                    )
                    edges.append(
                        GraphEdge(
                            source=target, target=subdomain, label="HAS_SUBDOMAIN"
                        )
                    )
    # Save to a new table

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_graphs (
            id INTEGER PRIMARY KEY,
            target TEXT NOT NULL,
            graph_data TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """
    )
    graph_data = {
        "nodes": [node.model_dump() for node in nodes.values()],
        "edges": [edge.model_dump() for edge in edges],
    }
    cursor.execute(
        "INSERT INTO entity_graphs (target, graph_data, timestamp) VALUES (?, ?, ?)",
        (target, json.dumps(graph_data), "2025-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    return EntityGraphResult(
        target=target,
        total_nodes=len(nodes),
        total_edges=len(edges),
        nodes=list(nodes.values()),
        edges=edges,
    )
