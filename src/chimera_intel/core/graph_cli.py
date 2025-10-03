"""
CLI commands for interacting with the Unified Graph Database.
"""

import typer
from rich.console import Console
from chimera_intel.core.graph_db import graph_db_instance

console = Console()
graph_app = typer.Typer(help="Interact with the Chimera Intelligence Graph.")


@graph_app.command("query")
def run_cypher_query(
    cypher_query: str = typer.Argument(..., help="The raw Cypher query to execute.")
):
    """
    Execute a raw Cypher query and print the results.
    """
    console.print(f"[bold cyan]Executing query:[/bold cyan] {cypher_query}")
    try:
        graph_db_instance.execute_query(cypher_query)
        console.print("[bold green]Query executed successfully.[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error executing query:[/bold red] {e}")


@graph_app.command("find-path")
def find_shortest_path(
    from_node: str = typer.Option(
        ..., "--from", help="Starting node (e.g., 'Domain:example.com')."
    ),
    to_node: str = typer.Option(..., "--to", help="Ending node (e.g., 'IP:1.2.3.4')."),
):
    """
    Finds the shortest path between two nodes in the graph.
    """
    try:
        from_label, from_name = from_node.split(":", 1)
        to_label, to_name = to_node.split(":", 1)

        query = (
            f"MATCH (start:{from_label} {{name: $start_name}}), (end:{to_label} {{name: $end_name}}), "
            "p = shortestPath((start)-[*]-(end)) "
            "RETURN p"
        )
        console.print(
            f"[bold cyan]Searching for path from {from_node} to {to_node}...[/bold cyan]"
        )
        # Note: This is a placeholder for result handling. A real implementation
        # would process and display the path results from a read_transaction.

        console.print(
            f"Execute this query in your Neo4j Browser to see the path:\n[yellow]{query}[/yellow]"
        )
    except ValueError:
        console.print(
            "[bold red]Error:[/bold red] Node format must be 'Label:Name' (e.g., 'Domain:example.com')."
        )
    except Exception as e:
        console.print(f"[bold red]An error occurred:[/bold red] {e}")
