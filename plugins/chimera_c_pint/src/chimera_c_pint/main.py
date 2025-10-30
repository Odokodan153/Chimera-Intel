import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import c_pint


class CPINTPlugin(ChimeraPlugin):
    """
    Integrated Cyber-Physical Systems Intelligence (C-PINT) plugin.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera cpint'."""
        return "cpint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'cpint' command."""
        return c_pint.app

    def initialize(self):
        """Initializes the C-PINT plugin."""
        pass


# The plugin manager will discover and instantiate this class
plugin = CPINTPlugin()
