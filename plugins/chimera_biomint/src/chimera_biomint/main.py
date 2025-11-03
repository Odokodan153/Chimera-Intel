"""
Biometric Intelligence (BIOMINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.biomint import biomint_app


class BiomintPlugin(ChimeraPlugin):
    """BIOMINT plugin for face and voice analysis."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera biomint')
        return "biomint"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return biomint_app

    def initialize(self):
        """Initializes the BIOMINT plugin."""
        pass