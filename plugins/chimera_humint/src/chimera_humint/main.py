"""
Human Intelligence (HUMINT) Management Plugin for Chimera Intel.
This plugin now also serves as an aggregator for core operational commands.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.humint import humint_app
from chimera_intel.core.cognitive_warfare_engine import cognitive_warfare_app


class HumintPlugin(ChimeraPlugin):
    """
    A plugin that groups core operational commands under a single entry point.
    """

    @property
    def name(self) -> str:
        """
        The name for this command group in the main CLI.
        e.g., 'chimera ops'
        """
        return "ops"

    @property
    def app(self) -> typer.Typer:
        """
        Returns the aggregated Typer app containing the sub-commands.
        """
        # Create a new Typer app instance that will be exposed by the plugin.
        humanOps_app = typer.Typer(help="Core operational commands for HUMINT and Cognitive Warfare.")

        # Add the core command groups to this new app instance.
        humanOps_app.add_typer(humint_app, name="humint")
        humanOps_app.add_typer(cognitive_warfare_app, name="cognitive-warfare")

        return humanOps_app

    def initialize(self):
        """Initializes the plugin."""
        pass