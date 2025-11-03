"""
Real-Time Feed Mesh Plugin for Chimera Intel.

This plugin:
1. Exposes the 'feed-mesh' CLI command group (e.g., 'chimera feed-mesh start').
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.feed_mesh_integrations import feed_mesh_app
from chimera_intel.core.logger_config import setup_logging

logger = setup_logging()

class FeedMeshPlugin(ChimeraPlugin):
    """
    Exposes CLI commands for managing real-time feed services.
    """

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera feed-mesh')
        return "feed-mesh"

    @property
    def app(self) -> typer.Typer:
        return feed_mesh_app

    def initialize(self): 
        """
        Initializes the FeedMesh plugin.
        (This plugin has no auto-start logic, matching the pattern.)
        """
        logger.info("Initializing FeedMesh Plugin (CLI commands only).")
        pass