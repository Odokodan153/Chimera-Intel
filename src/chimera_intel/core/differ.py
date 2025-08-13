import typer
import sqlite3
import json
from rich.console import Console
from rich.panel import Panel
from rich.pretty import pprint
from jsondiff import diff, ADD, DELETE
from .database import DB_FILE

console = Console()

def get_last_two_scans(target: str, module: str) -> tuple[dict | None, dict | None]:
    """
    Retrieves the two most recent scans for a specific target and module from the database.

    Args:
        target (str): The primary target of the scan (e.g., a domain name).
        module (str): The name of the module to retrieve scans for (e.g., 'footprint').

    Returns:
        tuple[dict | None, dict | None]: A tuple containing the most recent scan
                                         and the previous scan as dictionaries.
                                         Returns (None, None) if not enough scans are found.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # SQL query to get the last 2 scans for the given target and module, ordered by time
        cursor.execute(
            "SELECT scan_data FROM scans WHERE target = ? AND module = ? ORDER BY timestamp DESC LIMIT 2",
            (target, module)
        )
        
        records = cursor.fetchall()
        conn.close()
        
        # Check how many records we found
        if len(records) < 2:
            console.print(f"[bold yellow]Warning:[/] Found {len(records)} scan(s) for '{target}' in module '{module}'. Need at least 2 to compare.")
            return None, None
            
        # The records are returned as tuples, so we access the first element
        # and parse the JSON string back into a Python dictionary.
        latest_scan = json.loads(records[0][0])
        previous_scan = json.loads(records[1][0])
        
        return latest_scan, previous_scan
        
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not fetch historical scans: {e}")
        return None, None

def format_diff(diff_result: dict) -> dict:
    """
    Simplifies the output from jsondiff into a more human-readable format.

    Args:
        diff_result (dict): The raw diff output from the jsondiff library.

    Returns:
        dict: A simplified dictionary showing 'added', 'removed', and 'changed' items.
    """
    # This is a simplified formatter. It can be made much more sophisticated.
    # We focus on the most common changes: additions and deletions.
    changes = {
        "added": [],
        "removed": []
    }
    for key, value in diff_result.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_value == ADD:
                    changes["added"].append(f"{key}.{sub_key}")
                elif sub_value == DELETE:
                    changes["removed"].append(f"{key}.{sub_key}")
    return changes


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

    # Step 1: Get the data from the database
    latest, previous = get_last_two_scans(target, module)
    
    if not latest or not previous:
        raise typer.Exit()
        
    # Step 2: Calculate the difference between the two JSON structures
    # We can ignore certain keys that always change, like timestamps.
    difference = diff(previous, latest, syntax='symmetric', dump=True)
    difference_json = json.loads(difference)

    # Step 3: Present the results
    console.print("\n[bold]Comparison Results:[/bold]")
    
    if not difference_json:
        console.print("[bold green]No changes detected between the last two scans.[/bold green]")
    else:
        # Using rich's pretty print for a nice visual output of the changes
        pprint(difference_json)