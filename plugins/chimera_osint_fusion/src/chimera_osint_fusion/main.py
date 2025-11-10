"""
(NEW) OSINT Fusion Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.osint_fusion import osint_app


class OsintFusionPlugin(ChimeraPlugin):
    """(NEW) OSINT Fusion Hub plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name
        # e.g., 'chimera osint-fusion'
        return "osint-fusion"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return osint_app

    def initialize(self):
        """Initializes the plugin."""
        pass