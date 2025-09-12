"""Module for managing Intelligence Projects.

Handles the creation, loading, and context switching for different
investigation projects, allowing for persistent and organized intelligence gathering.
"""

import os
import yaml
import typer
import logging
from datetime import datetime
from typing import Optional, List

from .schemas import ProjectConfig, DaemonConfig
from .utils import console

logger = logging.getLogger(__name__)

PROJECTS_DIR = "chimera_projects"
CONTEXT_FILE = ".chimera_context"


def initialize_project_dir():
    """Ensures the main projects directory exists."""
    os.makedirs(PROJECTS_DIR, exist_ok=True)


def list_projects() -> List[str]:
    """Returns a list of all existing project names."""
    initialize_project_dir()
    try:
        return [
            d
            for d in os.listdir(PROJECTS_DIR)
            if os.path.isdir(os.path.join(PROJECTS_DIR, d))
        ]
    except FileNotFoundError:
        return []


def get_project_config_by_name(project_name: str) -> Optional[ProjectConfig]:
    """Loads a specific project's configuration by its name."""
    config_file_path = os.path.join(PROJECTS_DIR, project_name, "project.yaml")
    if not os.path.exists(config_file_path):
        logger.warning(f"Project '{project_name}' has a missing config file.")
        return None
    try:
        with open(config_file_path, "r") as f:
            config_data = yaml.safe_load(f)
        return ProjectConfig(**config_data)
    except Exception as e:
        logger.error(f"Could not load project config for '{project_name}': {e}")
        return None


def create_project(
    project_name: str,
    domain: str,
    company_name: Optional[str],
    ticker: Optional[str],
) -> bool:
    """Creates a new project directory and its configuration file.

    Args:
        project_name (str): A unique name for the new project.
        domain (str): The primary domain of the target.
        company_name (Optional[str]): The legal name of the target company.
        ticker (Optional[str]): The stock ticker of the target.

    Returns:
        bool: True if the project was created successfully, False otherwise.
    """
    initialize_project_dir()
    project_path = os.path.join(PROJECTS_DIR, project_name)
    if os.path.exists(project_path):
        logger.error(f"Project '{project_name}' already exists.")
        return False
    os.makedirs(project_path)
    config_file_path = os.path.join(project_path, "project.yaml")

    project_data = ProjectConfig(
        project_name=project_name,
        created_at=datetime.now().isoformat(),
        domain=domain,
        company_name=company_name,
        ticker=ticker,
        daemon_config=DaemonConfig(),  # Add default daemon config
    )

    try:
        with open(config_file_path, "w") as f:
            yaml.dump(
                project_data.model_dump(exclude_none=True), f, default_flow_style=False
            )
        logger.info(f"Successfully created project '{project_name}' at {project_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to create project configuration file: {e}")
        return False


def set_project_context(project_name: str) -> bool:
    """Sets the active project by writing its name to the context file.

    Args:
        project_name (str): The name of the project to activate.

    Returns:
        bool: True if the context was set successfully, False otherwise.
    """
    project_path = os.path.join(PROJECTS_DIR, project_name)
    if not os.path.exists(project_path):
        logger.error(f"Project '{project_name}' not found.")
        return False
    try:
        with open(CONTEXT_FILE, "w") as f:
            f.write(project_name)
        logger.info(f"Set active project context to '{project_name}'.")
        return True
    except Exception as e:
        logger.error(f"Failed to set project context: {e}")
        return False


def get_active_project() -> Optional[ProjectConfig]:
    """Gets the configuration for the currently active project.

    It reads the project name from the context file and then loads the
    corresponding project.yaml configuration.

    Returns:
        Optional[ProjectConfig]: A Pydantic model of the active project's
                                 configuration, or None if no project is active
                                 or if the configuration is invalid.
    """
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

    Args:
        target (Optional[str]): The target provided directly to the command.
        required_assets (List[str]): A list of asset types (e.g., "domain", "company_name")
                                     that are acceptable for this command from the project.

    Returns:
        str: The resolved target name.
    """
    if target:
        return target
    active_project = get_active_project()
    if active_project:
        # Try to find the first available required asset from the project

        for asset in required_assets:
            project_target = getattr(active_project, asset, None)
            if project_target:
                console.print(
                    f"[bold cyan]Using {asset.replace('_', ' ')} '{project_target}' from active project '{active_project.project_name}'.[/bold cyan]"
                )
                return project_target
        # If no required assets are found in the project

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
    project_name: str = typer.Argument(
        ..., help="The name of the project to activate."
    ),
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
