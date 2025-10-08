import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import dissemination_suite

class DisseminationPlugin(ChimeraPlugin):
    """
    Automated Dissemination & Briefing Suite plugin.
    This plugin focuses on ensuring the right intelligence gets to the right
    people in the right format at the right time.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera disseminate'."""
        return "disseminate"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'disseminate' command."""
        return dissemination_suite.app

    def initialize(self):
        """Initializes the Dissemination plugin."""
        pass

# The plugin manager will discover and instantiate this class
plugin = DisseminationPlugin()