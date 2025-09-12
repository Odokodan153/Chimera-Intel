"""
Project Management Plugin for Chimera Intel.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.project_manager import project_app
from chimera_intel.core.project_reporter import project_report_app
from chimera_intel.core.signal_analyzer import signal_app

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
        self.app.add_typer(project_report_app, name="report", help="Generate a comprehensive report for the active project.")
        self.app.add_typer(signal_app, name="signal", help="Analyzes data for unintentional strategic signals.")