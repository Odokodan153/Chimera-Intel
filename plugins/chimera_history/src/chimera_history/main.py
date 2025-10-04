"""
Historical Website Analysis Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.historical_analyzer import historical_app


class HistoricalPlugin(ChimeraPlugin):
    """Historical Website Analysis plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera historical')
        return "historical"

    @property
    def app(self) -> typer.Typer:
        # This points to the new Typer app instance in the core module
        return historical_app

    def initialize(self):
        """Initializes the Historical plugin."""
        pass