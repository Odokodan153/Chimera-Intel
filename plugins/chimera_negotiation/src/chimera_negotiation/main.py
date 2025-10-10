import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.negotiation.py import negotiation_app  # Import the app from the consolidated engine.py

class NegotiationPlugin(ChimeraPlugin):
    """
    AI Negotiation Analysis plugin for Chimera Intel.
    This plugin registers the unified 'negotiation' command group.
    """

    @property
    def name(self) -> str:
        """The name of the command group for this plugin."""
        return "negotiation"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return negotiation_app

    def initialize(self):
        """Initializes the Negotiation plugin."""
        pass