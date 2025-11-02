import typer
import logging
from chimera_intel.core.plugin_interface import ChimeraPlugin

# --- Import the CLI app directly from the core module ---
# This is where the commands are now defined
from chimera_intel.core.advanced_media_analysis import cli_app

logger = logging.getLogger(__name__)

class AdvancedMediaPlugin(ChimeraPlugin):
    """
    A lightweight plugin that registers the commands defined in
    the 'advanced_media_analysis' core module.
    """
    
    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "Advanced Media Analyzer"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        # Return the app imported from the core module
        return cli_app

    def initialize(self):
        """A method to perform any setup for the plugin."""
        logger.info("Advanced Media Analyzer plugin initialized (commands loaded from core module).")

# This function is the entry point for the plugin manager
def get_plugin() -> ChimeraPlugin:
    return AdvancedMediaPlugin()