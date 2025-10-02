"""
Module to handle interactive actions from the entity relationship graph.
"""

import logging
from .vulnerability_scanner import run_vulnerability_scan
from .footprint import gather_footprint_data

logger = logging.getLogger(__name__)


async def run_graph_action(node_id: str, node_type: str, action: str) -> dict:
    """
    Executes a specific scan or action based on a node from the graph.

    Args:
        node_id (str): The ID of the node (e.g., an IP address or domain).
        node_type (str): The type of the node (e.g., 'IPAddress', 'Domain').
        action (str): The action to perform (e.g., 'scan_ports', 'find_subdomains').

    Returns:
        dict: A dictionary containing the status and result of the action.
    """
    logger.info(f"Executing graph action '{action}' on {node_type} '{node_id}'")

    if action == "scan_ports" and node_type == "IPAddress":
        vuln_result = run_vulnerability_scan(node_id)
        return {"status": "success", "result": vuln_result.model_dump()}
    elif action == "find_subdomains" and node_type == "Domain":
        footprint_result = await gather_footprint_data(node_id)
        return {"status": "success", "result": footprint_result.model_dump()}
    else:
        return {
            "status": "error",
            "message": f"Action '{action}' not supported for node type '{node_type}'.",
        }
