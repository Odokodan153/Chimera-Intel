import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.hackernews import app as hackernews_app

class HackerNewsPlugin(ChimeraPlugin):
    """
    HackerNews plugin.
    Provides tools to fetch and display the top stories from Hacker News.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera hackernews'."""
        return "hackernews"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'hackernews' command."""
        plugin_app = typer.Typer(
            name="hackernews",
            help="Hacker News (HackerNews) Module.",
            no_args_is_help=True
        )
        
        plugin_app.add_typer(hackernews_app, name="run")
        
        return plugin_app

    def initialize(self):
        """Initializes the HackerNews plugin."""
        pass

# The plugin manager will discover and instantiate this class
plugin = HackerNewsPlugin()