"""
Cyber & Technology (CyTech) Intelligence Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.cytech_intel import cytech_intel_app


class CyTechIntelPlugin(ChimeraPlugin):
    """Cyber & Technology (CyTech) Intelligence plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera cytech-intel')
        return "cytech-intel"

    @property
    def app(self) -> typer.Typer:
        # This points to the new Typer app instance
        return cytech_intel_app

    def initialize(self):
        """Initializes the CyTech Intelligence plugin."""
        pass