"""Module for managing Intelligence Projects.

Handles the creation, loading, and context switching for different
investigation projects, allowing for persistent and organized intelligence gathering.
Now uses a PostgreSQL database for multi-user collaboration.
"""

import os
import typer
import logging
from datetime import datetime
from typing import Optional, List
import json

from .schemas import ProjectConfig
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
