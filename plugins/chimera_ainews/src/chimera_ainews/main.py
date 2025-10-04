import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.ainews import app as ainews_app

class AiNewsPlugin(ChimeraPlugin):
    """
    AINews (Artificial Intelligence News) plugin.
    Provides tools to fetch and display the latest news and developments
    in the AI industry.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera ainews'."""
        return "ainews"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'ainews' command."""
        plugin_app = typer.Typer(
            name="ainews",
            help="Artificial Intelligence News (AINews) Module.",
            no_args_is_help=True
        )
        
        plugin_app.add_typer(ainews_app, name="run")
        
        return plugin_app

    def initialize(self):
        """Initializes the AINews plugin."""
        pass

# The plugin manager will discover and instantiate this class
plugin = AiNewsPlugin()