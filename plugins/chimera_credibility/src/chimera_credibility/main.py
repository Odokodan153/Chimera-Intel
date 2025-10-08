import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import credibility_assessor

class CredibilityPlugin(ChimeraPlugin):
    """
    Credibility Assessment plugin.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera credibility'."""
        return "credibility"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'credibility' command."""
        return credibility_assessor.app

    def initialize(self):
        """Initializes the Credibility Assessment plugin."""
        pass

# The plugin manager will discover and instantiate this class
plugin = CredibilityPlugin()