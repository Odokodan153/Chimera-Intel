"""
Attack Path Simulator for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from rich.console import Console
from rich.panel import Panel
import networkx as nx
import psycopg2
import logging  

from .database import get_db_connection

console = Console()
logger = logging.getLogger(__name__)  # <-- FIX 2: Define the logger

attack_path_app = typer.Typer(
    name="attack-path",
    help="Simulates potential attack paths through a network or system.",
)


def build_attack_graph(cursor):
    """
    Builds an attack graph from assets and vulnerabilities in the database.
    """
    cursor.execute("SELECT source, target FROM asset_connections")
    connections = cursor.fetchall()
    graph = nx.DiGraph()
    for source, target in connections:
        graph.add_edge(source, target)
    return graph


@attack_path_app.command("simulate", help="Simulate an attack path to a target asset.")
def simulate_attack(
    entry_point: Annotated[
        str,
        typer.Option(
            "--entry-point",
            "-e",
            help="The entry point of the simulated attack (e.g., 'Public-Facing Web Server').",
        ),
    ],
    target_asset: Annotated[
        str,
        typer.Option(
            "--target-asset",
            "-t",
            help="The target asset to simulate the attack against (e.g., 'Customer Database').",
        ),
    ],
):
    """
    Simulates attack paths from an entry point to a target asset using data
    from the asset graph database.
    """
    logger.info(f"Simulating attack path from {entry_point} to {target_asset}")
    console.print(
        f"Simulating attack path from '[bold cyan]{entry_point}[/bold cyan]' to '[bold red]{target_asset}[/bold red]'..."
    )
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if assets exist at all

        cursor.execute("SELECT COUNT(*) FROM asset_connections")
        asset_count = cursor.fetchone()[0]
        if asset_count == 0:
            console.print(
                "[bold yellow]Warning:[/bold yellow] No assets found in the graph database. Cannot build attack graph."
            )
            raise typer.Exit(code=1)
        attack_graph = build_attack_graph(cursor)
        cursor.close()
        conn.close()

        if not nx.has_path(attack_graph, entry_point, target_asset):
            console.print(
                f"[bold yellow]No potential attack path found from '{entry_point}' to '{target_asset}'.[/bold yellow]"
            )
            raise typer.Exit()
        # Find all shortest paths

        paths = list(nx.all_shortest_paths(attack_graph, entry_point, target_asset))
        console.print(
            Panel(
                "\n".join([" -> ".join(path) for path in paths]),
                title="[bold green]Simulated Attack Path(s)[/bold green]",
                border_style="green",
            )
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except nx.NodeNotFound as e:
        console.print(
            f"[bold red]Asset Not Found:[/bold red] {e}. Ensure the entry point and target exist in the asset graph."
        )
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]An error occurred during simulation:[/bold red] {e}")
        raise typer.Exit(code=1)