import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import ethint

class ETHINTPlugin(ChimeraPlugin):
    """
    Ethical Governance & Compliance Engine (ETHINT) plugin.
    This plugin provides an incorruptible, logic-based supervisor to ensure
    all platform operations are wielded responsibly.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera ethint'."""
        return "ethint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'ethint' command."""
        return ethint.app

    def initialize(self):
        """Initializes the ETHINT plugin."""
        pass

# The plugin manager will discover and instantiate this class
plugin = ETHINTPlugin()