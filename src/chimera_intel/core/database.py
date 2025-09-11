import sqlite3
import json
import datetime
from rich.console import Console
from typing import Dict, Any, Optional, List
from . import correlation_engine  # Import the new engine

console = Console()
DB_FILE = "chimera_intel.db"


def initialize_database() -> None:
    """
    Creates the SQLite database file and the 'scans' table if they don't already exist.
    """
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                scan_data TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not initialize database: {e}"
        )
    except Exception as e:
        console.print(
            f"[bold red]An unexpected error occurred during database initialization:[/] {e}"
        )


def save_scan_to_db(target: str, module: str, data: Dict[str, Any]) -> None:
    """
    Saves a completed scan's JSON data to the SQLite database.
    """
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().isoformat()
        scan_data_json = json.dumps(data, indent=4, default=str)
        cursor.execute(
            "INSERT INTO scans (target, module, scan_data, timestamp) VALUES (?, ?, ?, ?)",
            (target, module, scan_data_json, timestamp),
        )
        conn.commit()
        conn.close()
        console.print(
            f" [dim cyan]>[/dim cyan] [dim]Scan results for '{target}' saved to historical database.[/dim]"
        )
        # --- TRIGGER CORRELATION ENGINE ---

        correlation_engine.run_correlations(target, module, data)
    except sqlite3.Error as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not save scan to database: {e}"
        )
    except Exception as e:
        console.print(
            f"[bold red]An unexpected error occurred while saving to the database:[/] {e}"
        )


def get_aggregated_data_for_target(target: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves and aggregates the most recent scan data from relevant modules for a target.
    """
    aggregated_data: Dict[str, Any] = {"target": target, "modules": {}}
    modules_to_fetch = [
        "footprint",
        "web_analyzer",
        "business_intel",
        "social_analyzer",
    ]
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        cursor = conn.cursor()
        for module in modules_to_fetch:
            cursor.execute(
                "SELECT scan_data FROM scans WHERE target = ? AND module = ? ORDER BY timestamp DESC LIMIT 1",
                (target, module),
            )
            record = cursor.fetchone()
            if record:
                aggregated_data["modules"][module] = json.loads(record[0])
        conn.close()
        if not aggregated_data["modules"]:
            console.print(
                f"[bold yellow]Warning:[/] No historical data found for target '{target}'. Run scans first."
            )
            return None
        return aggregated_data
    except sqlite3.Error as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not aggregate data for target: {e}"
        )
        return None
    except Exception as e:
        console.print(
            f"[bold red]An unexpected error occurred while fetching aggregated data:[/] {e}"
        )
        return None


def get_scan_history() -> List[Dict[str, Any]]:
    """
    Retrieves all scan records from the database, ordered by the most recent first.
    """
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, target, module, timestamp, scan_data FROM scans ORDER BY timestamp DESC"
        )
        records = cursor.fetchall()
        conn.close()
        return [dict(row) for row in records]
    except sqlite3.Error as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not fetch scan history: {e}"
        )
        return []
    except Exception as e:
        console.print(
            f"[bold red]An unexpected error occurred while fetching scan history:[/] {e}"
        )
        return []


# --- NEW FUNCTION ---


def get_scan_history_for_target(target: str) -> List[Dict[str, Any]]:
    """
    Retrieves all scan records for a specific target, ordered by the most recent first.
    """
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, target, module, timestamp FROM scans WHERE target = ? ORDER BY timestamp DESC",
            (target,),
        )
        records = cursor.fetchall()
        conn.close()
        return [dict(row) for row in records]
    except sqlite3.Error as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not fetch scan history for target '{target}': {e}"
        )
        return []
    except Exception as e:
        console.print(
            f"[bold red]An unexpected error occurred while fetching scan history for target '{target}':[/] {e}"
        )
        return []
