"""
Project Management Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.project_manager import project_app, get_active_project
from chimera_intel.core.project_reporter import project_report_app
from chimera_intel.core.signal_analyzer import signal_app
from chimera_intel.core.database import get_all_scans_for_target
from chimera_intel.core.stix_converter import create_stix_bundle, import_stix_bundle
from chimera_intel.core.utils import console
from chimera_intel.core.user_manager import get_active_user


@project_app.command("export-stix")
def export_stix_command(
    target: str = typer.Argument(..., help="The target whose data you want to export."),
    output_file: str = typer.Option(
        ..., "--output", "-o", help="The path to save the STIX JSON file."
    ),
):
    """Exports all intelligence for a target to a STIX 2.1 bundle."""
    console.print(
        f"[bold cyan]Exporting data for '{target}' to STIX 2.1 format...[/bold cyan]"
    )

    scans = get_all_scans_for_target(target)
    if not scans:
        console.print(
            f"[bold red]Error:[/bold red] No data found for target '{target}' to export."
        )
        raise typer.Exit(code=1)
    stix_bundle_str = create_stix_bundle(target, scans)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(stix_bundle_str)
        console.print(
            f"[bold green]Successfully exported STIX bundle to {output_file}[/bold green]"
        )
    except Exception as e:
        console.print(f"[bold red]Error saving file:[/bold red] {e}")
        raise typer.Exit(code=1)


@project_app.command("import-stix")
def import_stix_command(
    file_path: str = typer.Argument(..., help="Path to the STIX 2.1 JSON bundle file.")
):
    """Imports a STIX 2.1 bundle into the active project."""
    active_project = get_active_project()
    active_user = get_active_user()

    if not active_project or not active_user:
        console.print(
            "[bold red]Error:[/bold red] An active project and logged-in user are required to import STIX data."
        )
        raise typer.Exit(code=1)
    # In a real app, we would get the project ID from the database
    # For this example, we'll assume a project_id of 1

    project_id = 1

    console.print(
        f"[bold cyan]Importing STIX bundle from '{file_path}' into project '{active_project.project_name}'...[/bold cyan]"
    )
    result = import_stix_bundle(file_path, project_id, active_user.id)

    if result["status"] == "success":
        console.print(f"[bold green]{result['message']}[/bold green]")
    else:
        console.print(
            f"[bold red]Error importing bundle:[/bold red] {result['message']}"
        )
        raise typer.Exit(code=1)


class ProjectPlugin(ChimeraPlugin):
    """Project Management plugin for Chimera Intel."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera project')

        return "project"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return project_app

    def initialize(self):
        """Initializes the Project plugin by adding its sub-commands."""
        # Register the sub-commands for the 'project' command group

        self.app.add_typer(
            project_report_app,
            name="report",
            help="Generate a comprehensive report for the active project.",
        )
        self.app.add_typer(
            signal_app,
            name="signal",
            help="Analyzes data for unintentional strategic signals.",
        )
