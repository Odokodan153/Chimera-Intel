"""
Internal Intelligence Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.internal import internal_app
from chimera_intel.core.traffic_analyzer import traffic_analyzer_app
from chimera_intel.core.wifi_analyzer import wifi_analyzer_app
from chimera_intel.core.insider_threat import (
    insider_threat_app,
)


class InternalPlugin(ChimeraPlugin):
    """Internal Intelligence plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera internal')

        return "internal"

    @property
    def app(self) -> typer.Typer:
        # Add subcommands from different modules

        internal_app.add_typer(traffic_analyzer_app, name="traffic")
        internal_app.add_typer(wifi_analyzer_app, name="wifi")
        internal_app.add_typer(insider_threat_app, name="insider")
        return internal_app

    def initialize(self):
        """Initializes the Internal Intelligence plugin."""
        pass
