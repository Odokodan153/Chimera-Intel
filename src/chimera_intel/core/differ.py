import typer
import sqlite3
import json
from rich.pretty import pprint
from jsondiff import diff  # type: ignore
from typing import Tuple, Optional, Dict, Any, List
from .database import DB_FILE, console
from .schemas import FormattedDiff, DiffResult
from .utils import send_slack_notification
from .config_loader import API_KEYS
import logging

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
        Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]: A tuple containing the most
        recent scan and the previous scan as dictionaries. Returns (None, None) if not
        enough scans are found.
    """
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT scan_data FROM scans WHERE target = ? AND module = ? ORDER BY timestamp DESC LIMIT 2",
            (target, module),
        )
        records = cursor.fetchall()
        conn.close()

        if len(records) < 2:
            return None, None
        latest_scan = json.loads(records[0][0])
        previous_scan = json.loads(records[1][0])

        return latest_scan, previous_scan
    except sqlite3.Error as e:
        logger.error("Database error fetching last two scans for '%s': %s", target, e)
        return None, None
    except Exception as e:
        logger.critical(
            "Unexpected error fetching last two scans for '%s': %s", target, e
        )
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
    from jsondiff import ADD, DELETE

    for key, value in diff_result.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_value == ADD:
                    changes["added"].append(f"{key}.{sub_key}")
                elif sub_value == DELETE:
                    changes["removed"].append(f"{key}.{sub_key}")
    return FormattedDiff(**changes)


# --- Typer CLI Application ---

diff_app = typer.Typer()


@diff_app.command("run")
def run_diff_analysis(
    target: str = typer.Argument(
        ..., help="The target whose history you want to compare."
    ),
    module: str = typer.Argument(
        ..., help="The specific scan module to compare (e.g., 'footprint')."
    ),
):
    """
    Compares the last two scans of a target to detect changes and sends a notification.

    Args:
        target (str): The target whose history you want to compare.
        module (str): The specific scan module to compare (e.g., 'footprint').
    """
    logger.info(
        "Starting change detection for target '%s' in module '%s'", target, module
    )

    latest, previous = get_last_two_scans(target, module)

    if not latest or not previous:
        logger.warning(
            "Not enough historical data to compare for '%s' in module '%s'. Found 0 or 1 scans.",
            target,
            module,
        )
        raise typer.Exit()
    raw_difference = diff(previous, latest, syntax="symmetric", dump=True)
    difference_json = json.loads(raw_difference)

    if not difference_json:
        logger.info(
            "No changes detected between the last two scans for '%s' in module '%s'.",
            target,
            module,
        )
        raise typer.Exit()
    logger.info("Changes detected for '%s' in module '%s'.", target, module)

    formatted_changes = format_diff_simple(difference_json)
    full_result = DiffResult(
        comparison_summary=formatted_changes, raw_diff=difference_json
    )

    console.print("\n[bold]Comparison Results:[/bold]")
    pprint(full_result.raw_diff)

    # --- Send Slack Notification ---

    slack_url = API_KEYS.slack_webhook_url
    if slack_url:
        added_count = len(full_result.comparison_summary.added)
        removed_count = len(full_result.comparison_summary.removed)
        message = (
            f"🔔 *Chimera Intel Change Alert* 🔔\n\n"
            f"Detected changes for target *{target}* in module *{module}*:\n"
            f"  - `Added`: {added_count} items\n"
            f"  - `Removed`: {removed_count} items\n\n"
            f"Please review the latest scan for details."
        )
        send_slack_notification(slack_url, message)
