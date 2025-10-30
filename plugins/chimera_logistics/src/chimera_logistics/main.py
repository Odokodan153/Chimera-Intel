import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import logistics_intel


class LogisticsPlugin(ChimeraPlugin):
    """
    Logistics Intelligence plugin.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera logistics'."""
        return "logistics"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'logistics' command."""
        return logistics_intel.app

    def initialize(self):
        """Initializes the Logistics Intelligence plugin."""
        pass


# The plugin manager will discover and instantiate this class
plugin = LogisticsPlugin()
