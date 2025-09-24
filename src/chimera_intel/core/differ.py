"""
Module for comparing historical scans to detect changes over time.

This module provides the core logic for the 'diff' command. It fetches the two
most recent scans for a given target and module from the database, compares them
using the 'jsondiff' library, and formats the differences into a human-readable
summary. It can also trigger notifications (e.g., to Slack and Microsoft Teams)
when changes are detected.
"""

import typer
import json
from rich.pretty import pprint
from rich.table import Table
from jsondiff import diff, symbols, insert  # type: ignore
from typing import Tuple, Optional, Dict, Any, List
from .database import console, get_db_connection
from .schemas import FormattedDiff, DiffResult, MicroSignal
from .utils import send_slack_notification, send_teams_notification
from .config_loader import API_KEYS
import logging
from .project_manager import get_active_project

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)


def get_last_two_scans(
    target: str, module: str
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Retrieves the two most recent scans for a specific target and module from the database.

    Args:
        target (str): The primary target of the scan (e.g., a domain name).
        module (str): The name of the module to retrieve scans for (e.g., 'footprint').

    Returns:
        A tuple containing the most recent scan and the previous scan as dictionaries.
        Returns (None, None) if not enough scans are found.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT scan_data FROM scans WHERE target = %s AND module = %s ORDER BY timestamp DESC LIMIT 2",
            (target, module),
        )
        records = cursor.fetchall()
        conn.close()
        if len(records) < 2:
            return None, None
        latest_scan = json.loads(records[0][0])
        previous_scan = json.loads(records[1][0])
        return latest_scan, previous_scan
    except Exception as e:
        logger.error("Database error fetching last two scans for '%s': %s", target, e)
        return None, None


def format_diff_simple(diff_result: dict) -> FormattedDiff:
    """
    Simplifies the output from jsondiff into a more human-readable format.

    Args:
        diff_result (dict): The raw diff output from the jsondiff library.

    Returns:
        FormattedDiff: A Pydantic model showing added and removed items.
    """
    changes: Dict[str, List[str]] = {"added": [], "removed": []}
    for key, value in diff_result.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_value == symbols.add:
                    changes["added"].append(f"{key}.{sub_key}")
                elif sub_value == symbols.delete:
                    changes["removed"].append(f"{key}.{sub_key}")
        # This handles cases where a list has changed

        elif isinstance(value, list) and len(value) == 2:
            old_val, new_val = value
            # If a dictionary becomes empty, treat it as a deletion of its keys.

            if isinstance(old_val, dict) and new_val == {}:
                for sub_key in old_val.keys():
                    changes["removed"].append(f"{key}.{sub_key}")
            else:
                changes["removed"].append(f"{key}: {value[0]}")
                changes["added"].append(f"{key}: {value[1]}")
    return FormattedDiff(**changes)


def analyze_diff_for_signals(diff_result: dict) -> List[MicroSignal]:
    """
    Analyzes a raw jsondiff result to identify and interpret significant changes.

    Args:
        diff_result (dict): The raw diff output from the jsondiff library.

    Returns:
        List[MicroSignal]: A list of interpreted signals.
    """
    signals: List[MicroSignal] = []
    # Rule 1: New IP Address Added

    if "A" in diff_result.get("footprint", {}).get("dns_records", {}):
        if insert in diff_result["footprint"]["dns_records"]["A"]:
            new_ips = diff_result["footprint"]["dns_records"]["A"][insert]
            signals.append(
                MicroSignal(
                    signal_type="Infrastructure Change",
                    description=f"New IP address(es) detected: {', '.join(new_ips)}",
                    confidence="High",
                    source_field="footprint.dns_records.A",
                )
            )
    # Rule 2: New Technology Detected

    if "tech_stack" in diff_result.get("web_analysis", {}):
        tech_changes = diff_result["web_analysis"]["tech_stack"].get("results", {})
        added_tech = []
        for key, value in tech_changes.items():
            if (
                isinstance(value, dict)
                and "technology" in value
                and insert in value["technology"]
            ):
                added_tech.append(value["technology"][insert])
        if added_tech:
            signals.append(
                MicroSignal(
                    signal_type="Technology Adoption",
                    description=f"New web technology adopted: {', '.join(added_tech)}",
                    confidence="Medium",
                    source_field="web_analysis.tech_stack.results",
                )
            )
    return signals


# --- Typer CLI Application ---


diff_app = typer.Typer()


@diff_app.command("run")
def run_diff_analysis(
    module: str = typer.Argument(
        ..., help="The specific scan module to compare (e.g., 'footprint')."
    ),
    target: Optional[str] = typer.Argument(
        None, help="The target to compare. Uses active project if not provided."
    ),
):
    """
    Compares the last two scans of a target to detect changes and sends a notification.
    """
    target_name = target
    if not target_name:
        active_project = get_active_project()
        if active_project and active_project.domain:
            target_name = active_project.domain
            console.print(
                f"[bold cyan]Using target '{target_name}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No target provided and no active project set."
            )
            raise typer.Exit(code=1)
    if not target_name:
        console.print(
            "[bold red]Error:[/bold red] A target is required for this command."
        )
        raise typer.Exit(code=1)
    logger.info(
        "Starting change detection for target '%s' in module '%s'", target_name, module
    )
    latest, previous = get_last_two_scans(target_name, module)
    if not latest or not previous:
        logger.warning(
            "Not enough historical data to compare for '%s' in module '%s'. Found 0 or 1 scans.",
            target_name,
            module,
        )
        raise typer.Exit()
    raw_difference = diff(previous, latest, syntax="symmetric", dump=True)
    difference_json = json.loads(raw_difference)
    if not difference_json:
        logger.info(
            "No changes detected between the last two scans for '%s' in module '%s'.",
            target_name,
            module,
        )
        raise typer.Exit()
    logger.info("Changes detected for '%s' in module '%s'.", target_name, module)

    formatted_changes = format_diff_simple(difference_json)
    detected_signals = analyze_diff_for_signals(difference_json)

    full_result = DiffResult(
        comparison_summary=formatted_changes,
        detected_signals=detected_signals,
        raw_diff=difference_json,
    )

    console.print("\n[bold]Comparison Results:[/bold]")
    pprint(full_result.raw_diff)

    if full_result.detected_signals:
        console.print("\n[bold yellow]💡 Interpreted Micro-Signals[/bold yellow]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Signal Type", style="cyan")
        table.add_column("Description")
        table.add_column("Confidence", style="green")
        for signal in full_result.detected_signals:
            table.add_row(signal.signal_type, signal.description, signal.confidence)
        console.print(table)
    # --- Send Slack Notification ---

    slack_url = API_KEYS.slack_webhook_url
    if slack_url:
        added_count = len(full_result.comparison_summary.added)
        removed_count = len(full_result.comparison_summary.removed)
        message = (
            f"🔔 *Chimera Intel Change Alert* 🔔\n\n"
            f"Detected changes for target *{target_name}* in module *{module}*:\n"
            f"  - `Added`: {added_count} items\n"
            f"  - `Removed`: {removed_count} items\n\n"
            f"Please review the latest scan for details."
        )
        send_slack_notification(slack_url, message)
    # --- Send Teams Notification ---

    teams_url = API_KEYS.teams_webhook_url
    if teams_url:
        added_count = len(full_result.comparison_summary.added)
        removed_count = len(full_result.comparison_summary.removed)
        teams_title = "Chimera Intel Change Alert"
        # Teams supports Markdown for rich formatting

        teams_message = (
            f"Detected changes for target **{target_name}** in module **{module}**:\n\n"
            f"- **Added**: {added_count} items\n\n"
            f"- **Removed**: {removed_count} items\n\n"
            "Please review the latest scan for details."
        )
        send_teams_notification(teams_url, teams_title, teams_message)
