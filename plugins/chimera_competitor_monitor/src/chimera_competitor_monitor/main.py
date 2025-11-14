"""
Competitor Leak Monitor Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.competitor_monitor import comp_mon_app


class CompetitorMonitorPlugin(ChimeraPlugin):
    """Competitor CI monitoring plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera comp-mon')
        return "comp-mon"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in our new module
        return comp_mon_app

    def initialize(self):
        """Initializes the plugin."""
        pass