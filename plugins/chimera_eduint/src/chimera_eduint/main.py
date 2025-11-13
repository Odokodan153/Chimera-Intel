# File: Chimera-Intel/plugins/chimera_eduint/src/chimera_eduint/main.py

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.eduint import app as eduint_app
import logging

logger = logging.getLogger(__name__)

class EduintPlugin(ChimeraPlugin):
    """
    Plugin for Educational & Research Intelligence (EDUINT).
    
    Provides tools to monitor universities, labs, patents, and
    curriculum changes to track sources of innovation.
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        # This defines the command name (e.g., 'chimera eduint')
        return "eduint"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        # This points to the Typer app instance in the core eduint module
        return eduint_app

    def initialize(self):
        """Initializes the EDUINT plugin."""
        logger.info("EDUINT plugin initialized.")
        pass