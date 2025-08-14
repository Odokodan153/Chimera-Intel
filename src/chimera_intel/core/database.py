import sqlite3
import json
import datetime
from rich.console import Console
from typing import Dict, Any, List, Optional

console = Console()
DB_FILE = "chimera_intel.db"

def initialize_database() -> None:
    """
    Creates the SQLite database file and the 'scans' table if they don't already exist.

    This function is designed to be called once when the main application starts up.
    It ensures that the database is ready to accept new scan records.
    The schema includes:
    - id: A unique integer for each record.
    - target: The primary target of the scan (e.g., 'google.com').
    - module: The name of the module that ran the scan (e.g., 'footprint').
    - scan_data: The full JSON result of the scan, stored as a text string.
    - timestamp: An ISO 8601 formatted timestamp of when the scan was saved.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                scan_data TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not initialize database: {e}")

def save_scan_to_db(target: str, module: str, data: Dict[str, Any]) -> None:
    """
    Saves a completed scan's JSON data to the SQLite database.

    Args:
        target (str): The primary target of the scan (e.g., a domain name).
        module (str): The name of the module that ran the scan (e.g., 'footprint').
        data (Dict[str, Any]): The dictionary containing the results of the scan.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        timestamp = datetime.datetime.now().isoformat()
        # Convert the dictionary to a JSON formatted string for storage in the TEXT field.
        scan_data_json = json.dumps(data, indent=4, default=str)
        
        cursor.execute(
            "INSERT INTO scans (target, module, scan_data, timestamp) VALUES (?, ?, ?, ?)",
            (target, module, scan_data_json, timestamp)
        )
        
        conn.commit()
        conn.close()
        console.print(f" [dim cyan]>[/dim cyan] [dim]Scan results for '{target}' saved to historical database.[/dim]")
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not save scan to database: {e}")

def get_aggregated_data_for_target(target: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves and aggregates the most recent scan data from all relevant modules for a target.

    This function queries the database for the latest scan data from the 'footprint',
    'web_analyzer', and 'business_intel' modules and combines them into a single,
    comprehensive dictionary for holistic analysis (e.g., by the strategist module).

    Args:
        target (str): The primary target of the scans (e.g., 'google.com').

    Returns:
        Optional[Dict[str, Any]]: An aggregated dictionary of all available data,
                                  or None if no data is found for the target.
    """
    aggregated_data: Dict[str, Any] = {"target": target, "modules": {}}
    modules_to_fetch = ["footprint", "web_analyzer", "business_intel", "social_analyzer"]
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        for module in modules_to_fetch:
            # For each module, get the single most recent scan for the specified target.
            cursor.execute(
                "SELECT scan_data FROM scans WHERE target = ? AND module = ? ORDER BY timestamp DESC LIMIT 1",
                (target, module)
            )
            record = cursor.fetchone() # Fetches the first row of the query result
            if record:
                # Add the data to our aggregated dictionary under the module's name
                aggregated_data["modules"][module] = json.loads(record[0])
        
        conn.close()

        # If after checking all modules, we still have no data, return None.
        if not aggregated_data["modules"]:
            console.print(f"[bold yellow]Warning:[/] No historical data found for target '{target}'. Run scans first.")
            return None
            
        return aggregated_data
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not aggregate data for target: {e}")
        return None