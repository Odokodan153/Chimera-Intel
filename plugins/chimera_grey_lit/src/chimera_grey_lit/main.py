import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.grey_literature import grey_lit_app

class GreyLitPlugin(ChimeraPlugin):
    """
    Plugin for Grey Literature Intelligence (GREYINT).
    """

    @property
    def name(self) -> str:
        return "grey-lit"

    @property
    def app(self) -> typer.Typer:
        return grey_lit_app

    def initialize(self):
        """Initialize the grey literature plugin."""
        pass

# This function is the required entry point for the plugin manager.
def load_plugin() -> ChimeraPlugin:
    return GreyLitPlugin()