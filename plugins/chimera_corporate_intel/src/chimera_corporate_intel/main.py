"""
Corporate & Strategic Intelligence Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.corporate_intel import corporate_intel_app


class CorporateIntelPlugin(ChimeraPlugin):
    """Corporate & Strategic Intelligence plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera corporate')

        return "corporate"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return corporate_intel_app

    def initialize(self):
        """Initializes the Corporate & Strategic Intelligence plugin."""
        pass
