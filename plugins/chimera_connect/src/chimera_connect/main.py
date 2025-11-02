"""
Messaging Platform (Connect) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.connect import connect_app


class ConnectPlugin(ChimeraPlugin):
    """Plugin for monitoring public messaging platforms."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera connect')
        return "connect"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return connect_app

    def initialize(self):
        """Initializes the Connect plugin."""
        pass