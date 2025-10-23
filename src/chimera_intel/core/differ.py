import typer
from rich.pretty import pprint
from rich.table import Table
from jsondiff import diff, insert  # type: ignore
from typing import Tuple, Optional, Dict, Any, List, Union
from chimera_intel.core.database import get_db_connection
from chimera_intel.core.schemas import FormattedDiff, DiffResult, MicroSignal
from chimera_intel.core.utils import (
    send_slack_notification,
    send_teams_notification,
    console,
)
from chimera_intel.core.config_loader import API_KEYS
import logging
from chimera_intel.core.project_manager import resolve_target


# Get a logger instance for this specific file


logger = logging.getLogger(__name__)


def get_last_two_scans(
    target: str, module: str
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Retrieves the two most recent scans for a specific target and module.

    Args:
        target (str): The primary target of the scan (e.g., a domain name).
        module (str): The name of the module to retrieve scans for.

    Returns:
        A tuple containing (latest_scan, previous_scan).
        Returns (None, None) if fewer than two scans are found.
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
        # The records are ordered from newest to oldest.

        return records[0][0], records[1][0]
    except Exception as e:
        logger.error("Database error fetching last two scans for '%s': %s", target, e)
        return None, None


def _flatten_dict(
    d: Union[Dict, List], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """
    Flattens a nested dictionary or list into a single-level dictionary.

    For example, `{'a': {'b': 1}}` becomes `{'a.b': 1}`.

    Args:
        d (Union[Dict, List]): The dictionary or list to flatten.
        parent_key (str): The base key to prepend to flattened keys.
        sep (str): The separator to use between keys.

    Returns:
        Dict[str, Any]: The flattened dictionary.
    """
    items: List[Tuple[str, Any]] = []
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = parent_key + sep + k if parent_key else k
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
    elif isinstance(d, list):
        for i, v in enumerate(d):
            # Heuristic to find a good unique key for list items for a cleaner path

            id_key = (
                v.get("domain") or v.get("technology") or v.get("id") or str(i)
                if isinstance(v, dict)
                else str(i)
            )
            new_key = f"{parent_key}.{id_key}"
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
    else:
        items.append((parent_key, d))
    return dict(items)


def format_diff_simple(
    previous_scan: Dict[str, Any], latest_scan: Dict[str, Any]
) -> FormattedDiff:
    """
    Compares two dictionaries and produces a simple, human-readable diff.

    This method flattens both input dictionaries and then compares their keys
    and values to identify additions, removals, and changes.

    Args:
        previous_scan (Dict[str, Any]): The older scan data.
        latest_scan (Dict[str, Any]): The newer scan data.

    Returns:
        FormattedDiff: A Pantic model containing lists of added, removed,
                       and changed items.
    """
    flat_previous = _flatten_dict(previous_scan)
    flat_latest = _flatten_dict(latest_scan)

    previous_keys = set(flat_previous.keys())
    latest_keys = set(flat_latest.keys())

    added_keys = latest_keys - previous_keys
    removed_keys = previous_keys - latest_keys
    common_keys = latest_keys & previous_keys

    changes = {"added": list(added_keys), "removed": list(removed_keys), "changed": []}

    for key in common_keys:
        if flat_previous[key] != flat_latest[key]:
            changes["removed"].append(f"{key}: {flat_previous[key]}")
            changes["added"].append(f"{key}: {flat_latest[key]}")
    return FormattedDiff(**changes)


def analyze_diff_for_signals(diff_result: dict) -> List[MicroSignal]:
    """
    Analyzes a raw jsondiff result to identify and interpret significant changes.

    This function applies a set of rules to the diff to find patterns that
    may indicate a strategic change (e.g., a new IP address).

    Args:
        diff_result (dict): The raw diff output from the jsondiff library.

    Returns:
        List[MicroSignal]: A list of interpreted signals.
    """
    signals: List[MicroSignal] = []
    # Rule: New 'A' record detected in DNS

    if (
        "footprint" in diff_result
        and isinstance(diff_result.get("footprint"), dict)
        and "dns_records" in diff_result["footprint"]
        and isinstance(diff_result["footprint"].get("dns_records"), dict)
        and "A" in diff_result["footprint"]["dns_records"]
        and isinstance(diff_result["footprint"]["dns_records"].get("A"), dict)
    ):
        if insert in diff_result["footprint"]["dns_records"]["A"]:
            
            # --- FIX APPLIED ---
            # new_ips_tuples is a list of (index, value) tuples, e.g., [(1, '2.2.2.2')]
            new_ips_tuples = diff_result["footprint"]["dns_records"]["A"][insert]
            
            if isinstance(new_ips_tuples, list):
                # We must extract only the values (the IPs) for the .join() call.
                just_the_ips = [str(ip_tuple[1]) for ip_tuple in new_ips_tuples]
            # --- END FIX ---

                signals.append(
                    MicroSignal(
                        signal_type="Infrastructure Change",
                        description=f"New IP address(es) detected: {', '.join(just_the_ips)}",
                        confidence="High",
                        source_field="footprint.dns_records.A",
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
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="The target to compare. Uses active project if not provided.",
    ),
):
    """
    Compares the last two scans of a target to detect changes.

    This command fetches the two most recent scans for a given target and module,
    computes the difference, and prints a summary. If changes are found and
    notification webhooks (Slack, Teams) are configured, it will send an alert.
    """
    try:
        target_name = resolve_target(target, required_assets=["domain"])
    except typer.Exit as e:
        raise typer.Exit(code=e.exit_code)
    latest, previous = get_last_two_scans(target_name, module)
    if previous is None or latest is None:
        console.print(
            "[bold yellow]Not enough historical data to perform a comparison.[/bold yellow]"
        )
        return
    # Generate both the raw diff for signal analysis and the simple diff for display

    raw_difference = diff(previous, latest, syntax="symmetric")
    if not raw_difference:
        console.print("[bold green]No changes detected.[/bold green]")
        return
    formatted_changes = format_diff_simple(previous, latest)
    detected_signals = analyze_diff_for_signals(raw_difference)
    full_result = DiffResult(
        comparison_summary=formatted_changes,
        detected_signals=detected_signals,
        raw_diff=raw_difference,
    )

    console.print("\n[bold]Comparison Results:[/bold]")
    pprint(full_result.comparison_summary.model_dump())

    if full_result.detected_signals:
        console.print("\n[bold yellow]💡 Interpreted Micro-Signals[/bold yellow]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Signal Type", style="cyan")
        table.add_column("Description")
        table.add_column("Confidence", style="green")
        for signal in full_result.detected_signals:
            table.add_row(signal.signal_type, signal.description, signal.confidence)
        console.print(table)
    # Notifications

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
    teams_url = API_KEYS.teams_webhook_url
    if teams_url:
        added_count = len(full_result.comparison_summary.added)
        removed_count = len(full_result.comparison_summary.removed)
        teams_message = (
            f"Detected changes for target **{target_name}** in module **{module}**:\n\n"
            f"- **Added**: {added_count} items\n\n"
            f"- **Removed**: {removed_count} items\n\n"
            "Please review the latest scan for details."
        )
        send_teams_notification(teams_url, "Chimera Intel Change Alert", teams_message)