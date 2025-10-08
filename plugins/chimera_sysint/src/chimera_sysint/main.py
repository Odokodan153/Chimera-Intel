import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import sysint

class SYSINTPlugin(ChimeraPlugin):
    """
    Systemic Intelligence (SYSINT) & Cascade Analyzer plugin.
    This plugin provides tools to model and analyze entire complex systems
    (e.g., financial markets, energy grids) as single, integrated entities.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera sysint'."""
        return "sysint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'sysint' command."""
        return sysint.app

    def initialize(self):
        """Initializes the SYSINT plugin."""
        pass

# The plugin manager will discover and instantiate this class
plugin = SYSINTPlugin()