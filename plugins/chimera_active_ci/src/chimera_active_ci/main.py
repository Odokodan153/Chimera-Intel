"""
Active Counter-Intelligence (Active-CI) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the Typer app from the core counter_intelligence module
from chimera_intel.core.counter_intelligence import counter_intel_app


class ActiveCounterIntelPlugin(ChimeraPlugin):
    """Active-CI plugin for domain/brand monitoring, honey assets, and legal templates."""

    @property
    def name(self) -> str:
        """This defines the top-level command name: 'chimera active-ci'"""
        return "active-ci"

    @property
    def app(self) -> typer.Typer:
        """This points to the Typer app instance in the core module."""
        return counter_intel_app

    def initialize(self):
        """Initializes the Active-CI plugin."""
        # No specific initialization needed for this plugin
        pass