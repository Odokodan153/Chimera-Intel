"""
OSINT Watch Tower Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.watch_tower import watch_tower_app


class WatchTowerPlugin(ChimeraPlugin):
    """OSINT Watch Tower (Text-based Page Monitoring) plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera watch-tower')
        return "watch-tower"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in our new module
        return watch_tower_app

    def initialize(self):
        """Initializes the plugin."""
        pass