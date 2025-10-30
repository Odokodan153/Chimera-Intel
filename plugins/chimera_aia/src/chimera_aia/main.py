import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import aia_framework


class AIAPlugin(ChimeraPlugin):
    """
    Autonomous Intelligence Agent (AIA) Framework plugin.
    This plugin provides a virtual, AI-powered analyst that can
    independently manage intelligence tasks from start to finish using
    an advanced reasoning engine.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera aia'."""
        return "aia"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'aia' command."""
        return aia_framework.app

    def initialize(self):
        """Initializes the AIA Framework plugin."""
        pass


# The plugin manager will discover and instantiate this class
plugin = AIAPlugin()
