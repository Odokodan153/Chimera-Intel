"""
Advanced Reconnaissance Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.recon import recon_app


class ReconPlugin(ChimeraPlugin):
    """Advanced Reconnaissance plugin for specific intelligence data."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera recon')

        return "recon"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return recon_app

    def initialize(self):
        """Initializes the Advanced Reconnaissance plugin."""
        pass
