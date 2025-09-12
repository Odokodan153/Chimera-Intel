"""
Reporting & Visualization Plugin for Chimera Intel.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.reporter import report_app
from chimera_intel.core.grapher import graph_app

class ReportPlugin(ChimeraPlugin):
    """Reporting & Visualization plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera report')
        return "report"

    @property
    def app(self) -> typer.Typer:
        # We create a new Typer app here to register all the sub-commands
        report_group_app = typer.Typer(
            help="Generate reports from saved JSON scan data."
        )
        report_group_app.add_typer(report_app, name="pdf", help="Generate a formal PDF report.")
        report_group_app.add_typer(
            graph_app, name="graph", help="Generate a visual, interactive HTML graph."
        )
        return report_group_app

    def initialize(self):
        """Initializes the Reporting & Visualization plugin."""
        pass