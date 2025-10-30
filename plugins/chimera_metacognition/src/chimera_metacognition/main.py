import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import metacognition


class MetacognitionPlugin(ChimeraPlugin):
    """
    Metacognition & Self-Improving AI Core plugin.
    This plugin gives Chimera the ability to understand, critique, and
    improve itself, enabling true artificial intelligence.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera metacognition'."""
        return "metacognition"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'metacognition' command."""
        return metacognition.app

    def initialize(self):
        """Initializes the Metacognition plugin."""
        pass


# The plugin manager will discover and instantiate this class
plugin = MetacognitionPlugin()
