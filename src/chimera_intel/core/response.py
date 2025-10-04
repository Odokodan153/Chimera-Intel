"""
Automated Response & Counter-Offensive Operations Module for Chimera Intel.
"""

import typer
from typing_extensions import Annotated
from typing import List
from rich.console import Console
from rich.table import Table
import subprocess

from .database import get_db
from .schemas import ResponseRule

console = Console()

response_app = typer.Typer(
    name="response",
    help="Manages automated defensive and counter-offensive actions.",
)


@response_app.command("create-rule", help="Create a new automated response rule.")
def create_rule(
    name: Annotated[
        str,
        typer.Option("--name", "-n", help="A unique name for the rule.", prompt=True),
    ],
    trigger: Annotated[
        str,
        typer.Option(
            "--trigger",
            "-t",
            help="The event that triggers the rule (e.g., 'dark-monitor:credential-leak').",
            prompt=True,
        ),
    ],
    actions: List[str] = typer.Option(
        ...,
        "--action",
        "-a",
        help="An action to execute. Can be specified multiple times.",
    ),
):
    """
    Creates a 'Threat-to-Action' rule that automatically triggers defensive
    actions based on intelligence findings.
    """
    db = next(get_db())
    db_rule = ResponseRule(name=name, trigger=trigger, actions=actions)
    db.add(db_rule)
    db.commit()
    console.print(
        f"[bold green]✅ Response rule '{name}' created successfully.[/bold green]"
    )
    console.print(f"   - [bold]Trigger:[/] {trigger}")
    console.print(f"   - [bold]Actions:[/] {', '.join(actions)}")


@response_app.command("list-rules", help="List all configured response rules.")
def list_rules():
    """Displays all automated response rules currently in the database."""
    db = next(get_db())
    rules = db.query(ResponseRule).all()
    if not rules:
        console.print("[yellow]No response rules found.[/yellow]")
        return
    table = Table(title="Automated Response Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("Trigger", style="green")
    table.add_column("Actions", style="yellow")

    for rule in rules:
        table.add_row(str(rule.id), rule.name, rule.trigger, ", ".join(rule.actions))
    console.print(table)


@response_app.command(
    "execute-trigger", help="Find and execute the actions for a given trigger."
)
def execute_trigger(
    trigger: Annotated[
        str,
        typer.Argument(
            help="The trigger to execute (e.g., 'dark-monitor:credential-leak')."
        ),
    ],
):
    """
    Finds a rule matching a trigger and executes the defined actions.
    """
    console.print(f"Executing trigger: [bold cyan]{trigger}[/bold cyan]")
    db = next(get_db())
    rule = db.query(ResponseRule).filter(ResponseRule.trigger == trigger).first()

    if not rule:
        console.print("[yellow]No rule found for this trigger.[/yellow]")
        raise typer.Exit()
    console.print(f"Rule '{rule.name}' triggered. Executing actions:")
    for action in rule.actions:
        console.print(f"  - [bold]Executing action:[/] {action}")
        try:
            # We assume the action is a valid shell command.
            # In a real-world scenario, you would have a more robust action mapping system.

            process = subprocess.run(
                action,
                shell=True,
                check=True,
                capture_output=True,
                text=True,
            )
            console.print(f"    [green]Success![/green] Output: {process.stdout}")
        except subprocess.CalledProcessError as e:
            console.print(f"    [red]Error executing action:[/red] {e.stderr}")
        except Exception as e:
            console.print(f"    [red]An unexpected error occurred:[/red] {e}")
