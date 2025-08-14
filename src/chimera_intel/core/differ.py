import typer
import sqlite3
import json
from rich.console import Console
from rich.panel import Panel
from rich.pretty import pprint
from jsondiff import diff
from typing import Tuple, Optional, Dict, Any

# --- CORRECTED Absolute Imports ---
from .database import DB_FILE, console
# --- CHANGE: Import the new Pydantic models ---
from .schemas import FormattedDiff, DiffResult


def get_last_two_scans(target: str, module: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
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
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT scan_data FROM scans WHERE target = ? AND module = ? ORDER BY timestamp DESC LIMIT 2",
            (target, module)
        )
        records = cursor.fetchall()
        conn.close()
        
        if len(records) < 2:
            return None, None
            
        latest_scan = json.loads(records[0][0])
        previous_scan = json.loads(records[1][0])
        
        return latest_scan, previous_scan
        
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not fetch historical scans: {e}")
        return None, None

def format_diff_simple(diff_result: dict) -> FormattedDiff:
    """
    Simplifies the output from jsondiff into a more human-readable format.
    This is a basic formatter focusing on simple additions and deletions.

    Args:
        diff_result (dict): The raw diff output from the jsondiff library.

    Returns:
        FormattedDiff: A Pydantic model showing added and removed items.
    """
    changes = {
        "added": [],
        "removed": []
    }
    # jsondiff uses special sentinel values, which we can import and check against.
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
    target: str = typer.Argument(..., help="The target whose history you want to compare (e.g., 'google.com')."),
    module: str = typer.Argument(..., help="The specific scan module to compare (e.g., 'footprint').")
):
    """
    Compares the last two scans of a target to detect changes.
    """
    console.print(Panel(f"[bold yellow]Detecting Changes For:[/] {target} (Module: {module})", title="Chimera Intel | Change Detection", border_style="yellow"))

    latest, previous = get_last_two_scans(target, module)
    
    if not latest or not previous:
        console.print(f"[bold yellow]Warning:[/] Not enough historical data. Found 0 or 1 scan(s) for '{target}' in module '{module}'. Need at least 2 to compare.")
        raise typer.Exit()
        
    # The 'symmetric' syntax provides a clear before/after view.
    # `dump=True` makes it JSON-serializable.
    raw_difference = diff(previous, latest, syntax='symmetric', dump=True)
    difference_json = json.loads(raw_difference)

    if not difference_json:
        console.print("\n[bold green]No changes detected between the last two scans.[/bold green]")
        raise typer.Exit()

    # --- CHANGE: Structure the final result using the Pydantic model ---
    formatted_changes = format_diff_simple(difference_json)
    full_result = DiffResult(
        comparison_summary=formatted_changes,
        raw_diff=difference_json
    )

    console.print("\n[bold]Comparison Results:[/bold]")
    # Using rich's pretty print for a nice visual output of the raw JSON changes
    pprint(full_result.raw_diff)
    
    # You could optionally print the simplified summary as well:
    # console.print("\n[bold]Simplified Summary:[/bold]")
    # pprint(full_result.comparison_summary.model_dump())