"""
Offensive Reconnaissance Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.offensive import offensive_app


class OffensivePlugin(ChimeraPlugin):
    """Offensive Reconnaissance plugin for active scanning."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera offensive')

        return "offensive"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return offensive_app

    def initialize(self):
        """Initializes the Offensive Reconnaissance plugin."""
        pass
