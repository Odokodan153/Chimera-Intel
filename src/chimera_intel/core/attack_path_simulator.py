"""
Predictive Threat Modeling & Attack Path Simulation Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from rich.console import Console
from rich.panel import Panel
import networkx as nx
import json
from itertools import combinations

from chimera_intel.core.ai_core import perform_generative_task
from chimera_intel.core.database import get_db_connection
from chimera_intel.core.schemas import ScanModel

console = Console()

# Create a new Typer application for Attack Path Simulation commands


attack_path_simulator_app = typer.Typer(
    name="simulate",
    help="Predictive Threat Modeling & Attack Path Simulation.",
)


def build_attack_graph_from_db(project_name: str) -> dict:
    """
    Builds an attack graph by fetching real asset data from the database
    for a specific project.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, module, scan_data FROM scans WHERE project_id = (SELECT id FROM projects WHERE name = %s)",
        (project_name,),
    )
    scans = cursor.fetchall()
    cursor.close()
    conn.close()

    if not scans:
        raise ValueError(
            f"No assets found for project '{project_name}'. Run scans first."
        )
    G: nx.Graph = nx.Graph()
    for scan in scans:
        scan_data = ScanModel.model_validate(
            {"id": scan[0], "module": scan[1], "data": scan[2]}
        )
        node_id = f"{scan_data.module}_{scan_data.id}"
        G.add_node(node_id, type=scan_data.module, data=scan_data.data)
    # Add edges based on relationships between assets

    for node1, node2 in combinations(G.nodes(data=True), 2):
        data1 = node1[1]["data"]
        data2 = node2[1]["data"]

        # Example relationship: if two scans share a common IP address

        if "ip" in data1 and "ip" in data2 and data1["ip"] == data2["ip"]:
            G.add_edge(node1[0], node2[0], reason=f"Shared IP: {data1['ip']}")
        # Example relationship: if a domain resolves to an IP found in another scan

        if node1[1]["type"] == "footprint" and "A" in data1.get("footprint", {}).get(
            "dns_records", {}
        ):
            if "ip" in data2 and data2["ip"] in data1["footprint"]["dns_records"]["A"]:
                G.add_edge(node1[0], node2[0], reason=f"DNS Resolution: {data2['ip']}")
        if node2[1]["type"] == "footprint" and "A" in data2.get("footprint", {}).get(
            "dns_records", {}
        ):
            if "ip" in data1 and data1["ip"] in data2["footprint"]["dns_records"]["A"]:
                G.add_edge(node1[0], node2[0], reason=f"DNS Resolution: {data1['ip']}")
    nodes_for_prompt = []
    for node, attrs in G.nodes(data=True):
        nodes_for_prompt.append(
            {"id": node, "type": attrs["type"], "data": attrs.get("data", {})}
        )
    edges_for_prompt = []
    for u, v, attrs in G.edges(data=True):
        edges_for_prompt.append(
            {"source": u, "target": v, "reason": attrs.get("reason", "Unknown")}
        )
    return {
        "nodes": nodes_for_prompt,
        "edges": edges_for_prompt,
    }


@attack_path_simulator_app.command(
    name="attack", help="Simulate an attack path to a specified goal."
)
def simulate_attack(
    project_name: Annotated[
        str,
        typer.Option(
            "--project",
            "-p",
            help="The name of the project whose assets to use for the simulation.",
            prompt="Enter the project name",
        ),
    ],
    goal: Annotated[
        str,
        typer.Option(
            "--goal",
            "-g",
            help="The simulated attacker's goal (e.g., 'exfiltrate-data', 'access-database').",
            prompt="Enter the attacker's goal",
        ),
    ],
):
    """
    Simulates potential attack paths through a target's infrastructure and
    predicts which assets are most likely to be targeted.
    """
    console.print(
        f"Simulating attack path for project '[bold yellow]{project_name}[/bold yellow]' with goal: '[bold cyan]{goal}[/bold cyan]'"
    )

    try:
        # 1. Build the attack surface graph from the database

        attack_graph = build_attack_graph_from_db(project_name)

        # 2. Construct the prompt for the AI core

        prompt = (
            f"You are a cybersecurity expert specializing in attack path analysis. "
            f"Given the following list of discovered assets and their relationships for a project, identify the most likely multi-step attack path an adversary would take to achieve the goal: '{goal}'.\n\n"
            f"Network Assets and Relationships:\n{json.dumps(attack_graph, indent=2)}\n\n"
            f"Based on the asset types and their connections, describe the path step-by-step, explaining the likely TTPs for each stage."
        )

        # 3. Use the AI to generate the simulated attack path

        simulated_path = perform_generative_task(prompt)

        console.print(
            Panel(
                simulated_path,
                title="[bold green]Simulated Attack Path[/bold green]",
                border_style="green",
            )
        )
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(
            f"[bold red]An error occurred during attack simulation:[/bold red] {e}"
        )
        raise typer.Exit(code=1)
