import sqlite3
import json
import datetime
from rich.console import Console

# Initialize a console for any potential error messages
console = Console()
DB_FILE = "chimera_intel.db"

def initialize_database():
    """
    Creates the database and the 'scans' table if they don't already exist.
    This function is called once when the main application starts.
    """
    try:
        # Connect to the SQLite database. It will be created if it doesn't exist.
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # SQL statement to create a table named 'scans'
        # The table will store the scan target, the module used, the full JSON data,
        # and a timestamp for when the scan was performed.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                scan_data TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        
        # Commit the changes and close the connection
        conn.commit()
        conn.close()
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not initialize database: {e}")

def save_scan_to_db(target: str, module: str, data: dict):
    """
    Saves a completed scan's JSON data to the SQLite database.

    Args:
        target (str): The primary target of the scan (e.g., a domain name).
        module (str): The name of the module that ran the scan (e.g., 'footprint').
        data (dict): The dictionary containing the results of the scan.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get the current time in a standard ISO format
        timestamp = datetime.datetime.now().isoformat()
        
        # Convert the Python dictionary to a JSON formatted string
        scan_data_json = json.dumps(data, indent=4, default=str)
        
        # SQL statement to insert a new record into the 'scans' table
        cursor.execute(
            "INSERT INTO scans (target, module, scan_data, timestamp) VALUES (?, ?, ?, ?)",
            (target, module, scan_data_json, timestamp)
        )
        
        # Commit the changes and close the connection
        conn.commit()
        conn.close()
        # Print a confirmation message to the user in a dim style
        console.print(f" [dim cyan]>[/dim cyan] [dim]Scan results for '{target}' saved to historical database.[/dim]")
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not save scan to database: {e}")