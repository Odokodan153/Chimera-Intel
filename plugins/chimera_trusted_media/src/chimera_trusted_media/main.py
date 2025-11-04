# FILE: Chimera-Intel/plugins/chimera_trusted_media/src/chimera_trusted_media/main.py
"""
Trusted Media Workflow Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
import logging

logger = logging.getLogger(__name__)
from chimera_intel.core.trusted_media import trusted_media_app


class TrustedMediaPlugin(ChimeraPlugin):
    """
    Plugin for creating and registering auditable, trusted media.
    Provides workflows for watermarking, C2PA, and vault registration.
    """

    @property
    def name(self) -> str:
        """This defines the command name (e.g., 'chimera trusted-media')"""
        return "trusted-media"

    @property
    def app(self) -> typer.Typer:
        """This points to the existing Typer app instance in the core module"""
        return trusted_media_app

    def initialize(self):
        """Initializes the Trusted Media plugin."""
        if self.app is None:
            logger.error(
                "Trusted Media plugin could not be initialized (core app not loaded)."
            )
        else:
            logger.info("Trusted Media plugin initialized.")


# The plugin manager looks for this 'plugin' variable
plugin = TrustedMediaPlugin()