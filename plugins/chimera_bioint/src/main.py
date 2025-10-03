"""
Biological Intelligence (BIOINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.bioint import bioint_app


class BiointPlugin(ChimeraPlugin):
    """Biological Intelligence (BIOINT) plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera bioint')
        return "bioint"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return bioint_app

    def initialize(self):
        """Initializes the BIOINT plugin."""
        pass