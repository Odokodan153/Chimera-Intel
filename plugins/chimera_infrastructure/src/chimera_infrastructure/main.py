"""
Public Infrastructure & Utilities Intelligence Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.infrastructure_intel import infrastructure_intel_app


class InfrastructurePlugin(ChimeraPlugin):
    """Public Infrastructure & Utilities Intelligence plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera infrastructure-dependency')

        return "infrastructure-dependency"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return infrastructure_intel_app

    def initialize(self):
        """Initializes the Infrastructure Intelligence plugin."""
        pass
