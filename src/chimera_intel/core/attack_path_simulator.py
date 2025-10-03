"""
Predictive Threat Modeling & Attack Path Simulation Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from rich.console import Console
from rich.panel import Panel
import networkx as nx
import json

from chimera_intel.core.ai_core import perform_generative_task
from chimera_intel.core.database import get_db, Scans
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
    db = next(get_db())
    scans = db.query(Scans).filter(Scans.project_name == project_name).all()
    if not scans:
        raise ValueError(
            f"No assets found for project '{project_name}'. Run scans first."
        )
    G = nx.Graph()
    for scan in scans:
        scan_data = ScanModel.model_validate(scan)
        node_id = f"{scan_data.module}_{scan_data.id}"
        G.add_node(node_id, type=scan_data.module, data=scan_data.data)
    # In a full implementation, you would add sophisticated logic here to
    # create edges based on relationships between assets (e.g., IP to domain).
    # For now, we create a simplified representation for the AI.

    nodes_for_prompt = []
    for node, attrs in G.nodes(data=True):
        nodes_for_prompt.append({"id": node, "type": attrs["type"]})
    # Since edge logic is complex, we will just pass the list of assets to the AI
    # and let it infer the connections based on its knowledge.

    return {
        "nodes": nodes_for_prompt,
        "edges": "Not applicable in this simplified model.",
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
            f"Given the following list of discovered assets for a project, identify the most likely multi-step attack path an adversary would take to achieve the goal: '{goal}'.\n\n"
            f"Network Assets:\n{json.dumps(attack_graph['nodes'], indent=2)}\n\n"
            f"Based on the asset types, infer the connections and describe the path step-by-step, explaining the likely TTPs for each stage."
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
