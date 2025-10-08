import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import cryptocurrency_intel

class CryptoPlugin(ChimeraPlugin):
    """
    Cryptocurrency Intelligence plugin.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera crypto'."""
        return "crypto"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'crypto' command."""
        return cryptocurrency_intel.app

    def initialize(self):
        """Initializes the Cryptocurrency Intelligence plugin."""
        pass

# The plugin manager will discover and instantiate this class
plugin = CryptoPlugin()