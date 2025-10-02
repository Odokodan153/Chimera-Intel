"""
Physical OSINT Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.physical_osint import physical_osint_app


class PhysicalOsintPlugin(ChimeraPlugin):
    """Physical OSINT plugin that provides physical location scanning."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera physical')

        return "physical"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return physical_osint_app

    def initialize(self):
        """Initializes the Physical OSINT plugin."""
        pass
