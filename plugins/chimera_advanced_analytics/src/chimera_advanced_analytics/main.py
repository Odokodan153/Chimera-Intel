import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.advanced_analytics_cli import app as analytics_cli_app

class AdvancedAnalyticsPlugin(ChimeraPlugin):
    """
    A plugin for advanced AI analytics.
    Provides predictive simulation, narrative tracking, and risk scoring.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera analytics'."""
        return "analytics"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer app for the 'analytics' command."""

        return analytics_cli_app

    def initialize(self):
        """Initializes the Advanced Analytics plugin."""
        pass


# The plugin manager will discover and instantiate this class
plugin = AdvancedAnalyticsPlugin()