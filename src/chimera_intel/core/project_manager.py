"""Module for managing Intelligence Projects.

Handles the creation, loading, and context switching for different
investigation projects, allowing for persistent and organized intelligence gathering.
Now uses a PostgreSQL database for multi-user collaboration.
"""

import os
import typer
import logging
from datetime import datetime, timezone # <-- ADDED timezone
from typing import Optional, List
import json
from pydantic import BaseModel, Field # <-- ADDED

from .schemas import ProjectConfig, JudicialHoldResult # <-- ADDED JudicialHoldResult
from .utils import console
from .database import get_db_connection
from .user_manager import get_active_user, get_user_from_db

logger = logging.getLogger(__name__)

CONTEXT_FILE = ".chimera_context"


def list_projects() -> List[str]:
    """Returns a list of all project names the active user can access."""
    active_user = get_active_user()
    if not active_user:
        console.print(
            "[bold red]Error:[/bold red] You must be logged in to list projects."
        )
        return []
    projects = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT p.name FROM projects p
            JOIN project_users pu ON p.id = pu.project_id
            WHERE pu.user_id = %s
            ORDER BY p.name;
            """,
            (active_user.id,),
        )
        records = cursor.fetchall()
        projects = [record[0] for record in records]
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to list projects from database: {e}")
    return projects


def get_project_config_by_name(project_name: str) -> Optional[ProjectConfig]:
    """Loads a specific project's configuration from the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT config FROM projects WHERE name = %s", (project_name,))
        record = cursor.fetchone()
        cursor.close()
        conn.close()
        if record:
            config_data = record[0]
            if isinstance(config_data, str):
                config_data = json.loads(config_data)
            return ProjectConfig(**config_data)
        return None
    except Exception as e:
        logger.error(f"Could not load project config for '{project_name}': {e}")
        return None


def create_project(
    project_name: str,
    domain: str,
    company_name: Optional[str],
    ticker: Optional[str],
) -> bool:
    """Creates a new project in the database and assigns the creator as admin."""
    active_user = get_active_user()
    if not active_user:
        console.print(
            "[bold red]Error:[/bold red] You must be logged in to create a project."
        )
        return False
    project_data = ProjectConfig(
        project_name=project_name,
        created_at=datetime.now().isoformat(),
        domain=domain,
        company_name=company_name,
        ticker=ticker,
    )

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Insert the project

        cursor.execute(
            "INSERT INTO projects (name, config) VALUES (%s, %s) RETURNING id",
            (project_name, project_data.model_dump_json()),
        )
        project_id = cursor.fetchone()[0]
        # Assign the current user as the admin

        cursor.execute(
            "INSERT INTO project_users (project_id, user_id, role) VALUES (%s, %s, %s)",
            (project_id, active_user.id, "admin"),
        )
        conn.commit()
        cursor.close()
        conn.close()
        logger.info(f"User '{active_user.username}' created project '{project_name}'")
        return True
    except Exception as e:
        logger.error(f"Failed to create project '{project_name}' in database: {e}")
        return False


def add_user_to_project(project_name: str, username_to_add: str, role: str) -> bool:
    """Shares a project with another user."""
    # This would involve more complex permission checking in a real application
    # (e.g., checking if the active_user is an admin of the project).

    user_to_add = get_user_from_db(username_to_add)
    if not user_to_add:
        console.print(
            f"[bold red]Error:[/bold red] User '{username_to_add}' not found."
        )
        return False
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE name = %s", (project_name,))
        project_id = cursor.fetchone()[0]

        cursor.execute(
            "INSERT INTO project_users (project_id, user_id, role) VALUES (%s, %s, %s)",
            (project_id, user_to_add.id, role),
        )
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(
            f"Failed to share project '{project_name}' with user '{username_to_add}': {e}"
        )
        return False


def set_project_context(project_name: str) -> bool:
    """Sets the active project by writing its name to the context file."""
    # This part remains file-based as it's a local user setting.

    try:
        with open(CONTEXT_FILE, "w") as f:
            f.write(project_name)
        logger.info(f"Set active project context to '{project_name}'.")
        return True
    except Exception as e:
        logger.error(f"Failed to set project context: {e}")
        return False


def get_active_project() -> Optional[ProjectConfig]:
    """Gets the configuration for the currently active project."""
    if not os.path.exists(CONTEXT_FILE):
        return None
    try:
        with open(CONTEXT_FILE, "r") as f:
            project_name = f.read().strip()
        return get_project_config_by_name(project_name)
    except Exception as e:
        logger.error(f"Could not load active project: {e}")
        return None


def resolve_target(target: Optional[str], required_assets: List[str]) -> str:
    """
    Resolves the target for a command, prioritizing a direct argument over the active project.
    Exits if no valid target can be found.
    """
    if target:
        return target
    active_project = get_active_project()
    if active_project:
        for asset in required_assets:
            project_target = getattr(active_project, asset, None)
            if project_target:
                console.print(
                    f"[bold cyan]Using {asset.replace('_', ' ')} '{project_target}' from active project '{active_project.project_name}'.[/bold cyan]"
                )
                return project_target
        console.print(
            f"[bold red]Error:[/bold red] Active project '{active_project.project_name}' does not have the required asset for this command (needed one of: {', '.join(required_assets)})."
        )
        raise typer.Exit(code=1)
    else:
        console.print(
            "[bold red]Error:[/bold red] No target provided and no active project set. Use 'chimera project use <name>' or specify a target directly."
        )
        raise typer.Exit(code=1)


# --- ADDED: Real Judicial Hold Function ---

def set_judicial_hold(project_name: str, reason: str) -> JudicialHoldResult:
    """
    Places a project under judicial hold using a database transaction.
    
    This function performs three "real" actions:
    1. Sets an 'on_hold' flag in the 'projects' table.
    2. Copies all associated scans to an 'scan_results_archive' table.
    3. Logs the hold action to a 'judicial_holds' table.
    
    NOTE: This assumes you have:
    - Added `on_hold BOOLEAN DEFAULT FALSE` to your `projects` table.
    - Created a `judicial_holds` table.
    - Created a `scan_results_archive` table with the same schema as `scan_results`
      (plus maybe an `original_scan_id` column).
    """
    active_user = get_active_user()
    if not active_user:
        return JudicialHoldResult(
            project_name=project_name, 
            reason=reason, 
            set_by_user="Unknown",
            timestamp=datetime.now(timezone.utc).isoformat(),
            error="You must be logged in to set a judicial hold."
        )
    
    logger.info(f"User '{active_user.username}' attempting to place '{project_name}' on judicial hold.")
    
    conn = None
    snapshot_count = 0
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Start transaction
            
            # 1. Get project_id and lock the row for update
            cursor.execute("SELECT id, config FROM projects WHERE name = %s FOR UPDATE", (project_name,))
            record = cursor.fetchone()
            if not record:
                raise ValueError("Project not found.")
            
            project_id, config_data = record
            
            # Check if config is a dict (from JSONB) or str (from TEXT)
            if isinstance(config_data, str):
                config = json.loads(config_data)
            else:
                config = config_data
                
            if config.get("on_hold", False):
                 return JudicialHoldResult(
                    project_name=project_name,
                    reason=reason,
                    set_by_user=active_user.username,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    error="Project is already on judicial hold."
                )

            # 2. Update the project's config to set the on_hold flag
            # A dedicated 'on_hold' column is better, but this works with the current schema
            config["on_hold"] = True
            cursor.execute(
                "UPDATE projects SET config = %s WHERE id = %s",
                (json.dumps(config), project_id)
            )

            # 3. Create immutable snapshot by copying scan results
            # Assumes 'scan_results_archive' table exists
            cursor.execute(
                """
                INSERT INTO scan_results_archive (project_name, module, timestamp, result)
                SELECT project_name, module, timestamp, result
                FROM scan_results
                WHERE project_name = %s
                """,
                (project_name,)
            )
            snapshot_count = cursor.rowcount

            # 4. Log the hold action to the 'judicial_holds' table
            # Assumes 'judicial_holds' table exists
            cursor.execute(
                """
                INSERT INTO judicial_holds (project_id, user_id, reason, created_at)
                VALUES (%s, %s, %s, %s)
                """,
                (project_id, active_user.id, reason, datetime.now(timezone.utc))
            )
            
            # Commit the transaction
            conn.commit()
        
        logger.info(f"Successfully placed '{project_name}' on judicial hold. Archived {snapshot_count} scan results.")
        return JudicialHoldResult(
            project_name=project_name,
            hold_set=True,
            reason=reason,
            set_by_user=active_user.username,
            timestamp=datetime.now(timezone.utc).isoformat(),
            snapshot_details=f"Copied {snapshot_count} scan results to archive."
        )
        
    except Exception as e:
        if conn:
            conn.rollback() # Roll back transaction on error
        logger.error(f"Failed to set judicial hold for '{project_name}': {e}", exc_info=True)
        return JudicialHoldResult(
            project_name=project_name,
            reason=reason,
            set_by_user=active_user.username,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=f"Database error: {e}"
        )
    finally:
        if conn:
            conn.close()


# --- Typer CLI Application ---


project_app = typer.Typer()


@project_app.command("init")
def init_project_command(
    project_name: str = typer.Argument(..., help="A unique name for the new project."),
    domain: str = typer.Option(
        ..., "--domain", help="The primary domain of the target."
    ),
    company_name: Optional[str] = typer.Option(
        None, "--company", help="The legal name of the target company."
    ),
    ticker: Optional[str] = typer.Option(
        None, "--ticker", help="The stock ticker of the target."
    ),
):
    """Initializes a new intelligence project."""
    if create_project(project_name, domain, company_name, ticker):
        console.print(
            f"[bold green]Project '{project_name}' created successfully.[/bold green]"
        )
        set_project_context(project_name)
    else:
        raise typer.Exit(code=1)


@project_app.command("use")
def use_project_command(
    project_name: str = typer.Argument(..., help="The name of the project to activate.")
):
    """Sets the active project context for all subsequent commands."""
    if set_project_context(project_name):
        console.print(
            f"[bold green]Active project is now '{project_name}'.[/bold green]"
        )
    else:
        raise typer.Exit(code=1)


@project_app.command("status")
def status_command():
    """Shows the currently active project and its key assets."""
    active_project = get_active_project()
    if active_project:
        console.print(
            f"Active project: [bold cyan]{active_project.project_name}[/bold cyan]"
        )
        console.print(f"  - Domain: {active_project.domain}")
        if active_project.company_name:
            console.print(f"  - Company Name: {active_project.company_name}")
        if active_project.ticker:
            console.print(f"  - Ticker: {active_project.ticker}")
    else:
        console.print("No active project. Use 'chimera project use <name>' to set one.")


@project_app.command("share")
def share_project_command(
    project_name: str = typer.Argument(..., help="The name of the project to share."),
    username: str = typer.Option(
        ..., "--user", help="The username to share the project with."
    ),
    role: str = typer.Option(
        "analyst", "--role", help="The role to assign (admin, analyst, read-only)."
    ),
):
    """Shares a project with another user."""
    if add_user_to_project(project_name, username, role):
        console.print(
            f"[bold green]Successfully shared '{project_name}' with '{username}' as '{role}'.[/bold green]"
        )
    else:
        console.print("[bold red]Error:[/bold red] Could not share project.")
        raise typer.Exit(code=1)


@project_app.command("judicial-hold") # <-- ADDED
def judicial_hold_command(
    project_name: str = typer.Argument(..., help="The name of the project to place on hold."),
    reason: str = typer.Option(
        ..., "--reason", "-r", help="The legal reason for placing the hold (e.g., 'Litigation Case #1234')."
    ),
):
    """
    Places a project and its evidence under a legal hold.
    This flags the project and snapshots all current scan results to an archive.
    """
    result = set_judicial_hold(project_name, reason)
    if result.hold_set:
        console.print(
            f"[bold green]Successfully placed project '{project_name}' on judicial hold.[/bold green]"
        )
        console.print(f"  - Reason: {result.reason}")
        console.print(f"  - Set by: {result.set_by_user}")
        console.print(f"  - Snapshot: {result.snapshot_details}")
    else:
        console.print(f"[bold red]Error:[/bold red] Could not set judicial hold: {result.error}")
        raise typer.Exit(code=1)