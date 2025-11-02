"""
Chimera Intel Plugin for the Real-Time Event Mesh.

This file registers the Event Mesh Typer application (defined
in the core module) with the Chimera Intel plugin system.
"""

import typer
import logging
from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the pre-built Typer app from the core module
from chimera_intel.core.event_mesh import event_mesh_app


logger = logging.getLogger(__name__)


# --- Plugin Registration ---

class EventMeshPlugin(ChimeraPlugin):
    """Plugin for the Real-Time Event Mesh."""

    @property
    def name(self) -> str:
        return "event_mesh"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer app defined in the core module."""
        return event_mesh_app

    def initialize(self):
        """Called by the plugin manager on load."""
        logger.info("Event Mesh plugin initialized.")