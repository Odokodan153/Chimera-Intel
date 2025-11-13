# plugins/chimera_opdec/src/chimera_opdec/main.py

import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.opdec import app as opdec_app
from src.chimera_intel.core.utils import console

class OPDECPlugin(ChimeraPlugin):
    """
    Plugin for the Operational Deception (OPDEC) Engine.
    This registers the 'opdec' CLI command group.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera opdec'."""
        return "opdec"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer app for the 'opdec' command group."""
        return opdec_app

    def initialize(self):
        """
        Initializes the OPDEC plugin.
        """
        console.print(
            "[OPDEC Plugin] [bold green]Active[/bold green]. Analyst protection systems enabled."
        )


# The plugin manager will discover and instantiate this class
plugin = OPDECPlugin()