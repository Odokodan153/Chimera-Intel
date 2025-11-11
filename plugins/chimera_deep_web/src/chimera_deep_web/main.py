"""
Deep Web Intelligence Plugin for Chimera Intel.
Provides commands for searching academic and specialized databases via Google CSE.
"""

import typer
import logging
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.deep_web_analyzer import deep_web_app


class DeepWebPlugin(ChimeraPlugin):
    """
    Plugin for Deep Web Intelligence.
    """

    @property
    def name(self) -> str:
        # This will create a top-level command: `chimera-intel deep-web`
        return "deep-web"

    @property
    def app(self) -> typer.Typer:
        # Return the Typer app imported from the core module
        return deep_web_app

    def initialize(self):
        """Initializes the Deep Web plugin."""
        logging.info("Chimera Deep Web plugin initialized.")

# This function is the required entry point for the plugin manager.
def load_plugin() -> ChimeraPlugin:
    return DeepWebPlugin()