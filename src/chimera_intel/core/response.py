"""
Automated Incident Response Module for Chimera Intel.

This module provides functionalities to define automated response rules and
execute corresponding actions when specific triggers are met.
"""

import typer
from typing import List, Dict, Any
import psycopg2

from .config_loader import API_KEYS
from .utils import console, send_slack_notification, send_teams_notification
from .database import get_db_connection

response_app = typer.Typer(
    name="response",
    help="Manages automated incident response rules and actions.",
)

# A simple mapping of action names to functions.
# In a real-world scenario, these would be more complex integrations.

ACTION_MAP = {
    "send_slack_alert": lambda details: send_slack_notification(
        message=f"Automated Response Triggered: {details}"
    ),
    "send_teams_alert": lambda details: send_teams_notification(
        title="Automated Response", message=details
    ),
    "quarantine_host": lambda details: console.print(
        f"[bold yellow]ACTION (Simulated):[/bold yellow] Quarantining host mentioned in: {details}"
    ),
    "reset_password": lambda details: console.print(
        f"[bold yellow]ACTION (Simulated):[/bold yellow] Resetting password for user mentioned in: {details}"
    ),
}


def get_response_rule(trigger: str) -> List[str]:
    """Retrieves the actions for a given trigger from the database."""
    actions = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT actions FROM response_rules WHERE trigger = %s", (trigger,)
        )
        record = cursor.fetchone()
        cursor.close()
        conn.close()
        if record:
            return record[0]  # Actions are stored as a JSON list
    except (psycopg2.Error, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not retrieve response rule: {e}"
        )
    return actions


def execute_response_actions(trigger: str, event_details: str):
    """
    Executes the predefined response actions for a specific trigger.
    """
    console.print(f"\n[bold cyan]Event detected with trigger:[/bold cyan] '{trigger}'")
    console.print(f"[bold]Details:[/bold] {event_details}")

    actions_to_execute = get_response_rule(trigger)
    if not actions_to_execute:
        console.print(
            f"  - No response rule found for trigger '{trigger}'. No actions taken."
        )
        return
    console.print("[bold]Executing response actions:[/bold]")
    for action_name in actions_to_execute:
        action_func = ACTION_MAP.get(action_name)
        if action_func:
            console.print(f"  - Running action: [bold green]{action_name}[/bold green]")
            try:
                action_func(event_details)
            except Exception as e:
                console.print(
                    f"    [bold red]Error executing action '{action_name}':[/bold red] {e}"
                )
        else:
            console.print(
                f"  - [bold red]Warning:[/bold red] Action '{action_name}' is not defined in the ACTION_MAP."
            )


@response_app.command("add-rule")
def add_rule(
    trigger: str = typer.Option(
        ...,
        "--trigger",
        "-t",
        help="The trigger name (e.g., 'dark-web:credential-leak').",
    ),
    actions: List[str] = typer.Option(
        ...,
        "--action",
        "-a",
        help="An action to execute. Can be specified multiple times.",
    ),
):
    """
    Adds a new automated response rule to the database.
    """
    console.print(f"Adding response rule for trigger: [bold cyan]{trigger}[/bold cyan]")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Using INSERT ... ON CONFLICT to handle updates gracefully

        cursor.execute(
            """
            INSERT INTO response_rules (trigger, actions) VALUES (%s, %s)
            ON CONFLICT (trigger) DO UPDATE SET actions = EXCLUDED.actions;
            """,
            (trigger, actions),
        )
        conn.commit()
        cursor.close()
        conn.close()
        console.print(
            "[bold green]Successfully added/updated response rule.[/bold green]"
        )
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not add rule: {e}")


@response_app.command("simulate-event")
def simulate_event(
    trigger: str = typer.Argument(..., help="The trigger name to simulate."),
    details: str = typer.Argument(
        "Simulated event for testing purposes.", help="Details of the simulated event."
    ),
):
    """
    Simulates an event to test the response rules and actions.
    """
    execute_response_actions(trigger, details)
