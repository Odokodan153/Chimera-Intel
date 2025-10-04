"""
CLI commands for interacting with the Unified Graph Database.
"""

import typer
from rich.console import Console
from rich.table import Table
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
        results = graph_db_instance.execute_query(cypher_query)
        console.print("[bold green]Query executed successfully.[/bold green]")
        if results:
            # Create a table to display the results

            table = Table(show_header=True, header_style="bold magenta")
            if results:
                # Use the keys from the first record as headers

                headers = results[0].keys()
                for header in headers:
                    table.add_column(header)
                for record in results:
                    table.add_row(*[str(value) for value in record.values()])
            console.print(table)
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
        results = graph_db_instance.execute_query(
            query, {"start_name": from_name, "end_name": to_name}
        )

        if results:
            console.print("[bold green]Path found![/bold green]")
            for record in results:
                path = record["p"]
                nodes = path.nodes
                relationships = path.relationships

                path_str = ""
                for i, node in enumerate(nodes):
                    path_str += f"({node.get('name')})"
                    if i < len(relationships):
                        path_str += f"-[{relationships[i].type}]->"
                console.print(path_str)
        else:
            console.print("[yellow]No path found between the specified nodes.[/yellow]")
    except ValueError:
        console.print(
            "[bold red]Error:[/bold red] Node format must be 'Label:Name' (e.g., 'Domain:example.com')."
        )
    except Exception as e:
        console.print(f"[bold red]An error occurred:[/bold red] {e}")
