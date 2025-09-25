import psycopg2
import json
from typing import Dict, Any, Optional, List

from .schemas import User
from .config_loader import API_KEYS
from .utils import console


def get_db_connection():
    """Establishes a connection to the PostgreSQL database using credentials from the environment."""
    db_name = getattr(API_KEYS, "db_name", None)
    db_user = getattr(API_KEYS, "db_user", None)
    db_password = getattr(API_KEYS, "db_password", None)
    db_host = getattr(API_KEYS, "db_host", None)

    if not all([db_name, db_user, db_password, db_host]):
        console.print(
            "[bold red]Database Configuration Error:[/bold red] One or more database connection variables (DB_NAME, DB_USER, DB_PASSWORD, DB_HOST) are not set in your .env file."
        )
        raise ConnectionError("Database credentials not configured.")
    try:
        return psycopg2.connect(
            dbname=db_name, user=db_user, password=db_password, host=db_host
        )
    except psycopg2.OperationalError as e:
        console.print(
            f"[bold red]Database Connection Error:[/bold red] Could not connect to PostgreSQL. Is the database running and accessible? Error: {e}"
        )
        raise


def initialize_database() -> None:
    """
    Creates the necessary tables in the PostgreSQL database if they don't already exist.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            );
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id SERIAL PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                config JSONB NOT NULL
            );
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS project_users (
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'read-only')),
                PRIMARY KEY (project_id, user_id)
            );
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                scan_data JSONB NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                user_id INTEGER REFERENCES users(id),
                project_id INTEGER REFERENCES projects(id)
            );
            """
        )
        conn.commit()
        cursor.close()
        conn.close()
    except (Exception, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not initialize database: {e}"
        )


def create_user_in_db(username: str, hashed_password: str) -> None:
    """Creates a new user in the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, hashed_password) VALUES (%s, %s)",
            (username, hashed_password),
        )
        conn.commit()
        cursor.close()
        conn.close()
    except (psycopg2.Error, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not create user: {e}"
        )


def get_user_from_db(username: str) -> Optional[User]:
    """Retrieves a user from the database by their username."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, hashed_password FROM users WHERE username = %s",
            (username,),
        )
        record = cursor.fetchone()
        cursor.close()
        conn.close()
        if record:
            return User(id=record[0], username=record[1], hashed_password=record[2])
        return None
    except (psycopg2.Error, ConnectionError) as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not fetch user: {e}")
        return None


def save_scan_to_db(
    target: str,
    module: str,
    data: Dict[str, Any],
    user_id: Optional[int] = None,
    project_id: Optional[int] = None,
) -> None:
    """
    Saves a completed scan's JSON data to the PostgreSQL database.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        scan_data_json = json.dumps(data, indent=4, default=str)
        cursor.execute(
            "INSERT INTO scans (target, module, scan_data, user_id, project_id) VALUES (%s, %s, %s, %s, %s)",
            (target, module, scan_data_json, user_id, project_id),
        )
        conn.commit()
        cursor.close()
        conn.close()
        console.print(
            f" [dim cyan]>[/dim cyan] [dim]Scan results for '{target}' saved to historical database.[/dim]"
        )
    except (psycopg2.Error, ConnectionError) as e:
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
        "physical_osint_locations",
        "corporate_hr_intel",
        "ecosystem_analysis",
        "code_intel_repo",
        "defensive_breaches",
        "vulnerability_scanner",
        "cloud_osint",
        "recon_credentials",
    ]
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        for module in modules_to_fetch:
            cursor.execute(
                """
                SELECT scan_data FROM scans
                WHERE target = %s AND module = %s
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (target, module),
            )
            record = cursor.fetchone()
            if record:
                aggregated_data["modules"][module] = record[0]
        cursor.close()
        conn.close()

        if not aggregated_data["modules"]:
            console.print(
                f"[bold yellow]Warning:[/] No historical data found for target '{target}'. Run scans first."
            )
            return None
        return aggregated_data
    except (psycopg2.Error, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not aggregate data for target: {e}"
        )
        return None


def get_scan_history() -> List[Dict[str, Any]]:
    """
    Retrieves all scan records from the database, ordered by the most recent first.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, target, module, timestamp, scan_data FROM scans ORDER BY timestamp DESC"
        )
        records = cursor.fetchall()
        cursor.close()
        conn.close()
        return [
            {
                "id": r[0],
                "target": r[1],
                "module": r[2],
                "timestamp": r[3],
                "scan_data": r[4],
            }
            for r in records
        ]
    except (psycopg2.Error, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not fetch scan history: {e}"
        )
        return []


def get_scan_history_for_target(target: str) -> List[Dict[str, Any]]:
    """
    Retrieves all scan records for a specific target, ordered by the most recent first.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, target, module, timestamp FROM scans WHERE target = %s ORDER BY timestamp DESC",
            (target,),
        )
        records = cursor.fetchall()
        cursor.close()
        conn.close()
        return [
            {"id": r[0], "target": r[1], "module": r[2], "timestamp": r[3].isoformat()}
            for r in records
        ]
    except (psycopg2.Error, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not fetch scan history for target '{target}': {e}"
        )
        return []


def get_all_scans_for_target(
    target: str, module: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves all historical scans for a specific target, optionally filtered by module.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if module:
            cursor.execute(
                "SELECT scan_data, timestamp FROM scans WHERE target = %s AND module = %s ORDER BY timestamp ASC",
                (target, module),
            )
        else:
            cursor.execute(
                "SELECT scan_data, timestamp FROM scans WHERE target = %s ORDER BY timestamp ASC",
                (target,),
            )
        records = cursor.fetchall()
        cursor.close()
        conn.close()
        return [{"scan_data": r[0], "timestamp": r[1]} for r in records]
    except (psycopg2.Error, ConnectionError) as e:
        console.print(
            f"[bold red]Database Error:[/bold red] Could not fetch scans for target: {e}"
        )
        return []
