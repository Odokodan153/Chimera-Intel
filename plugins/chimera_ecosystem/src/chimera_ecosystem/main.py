"""
Ecosystem Intelligence Plugin for Chimera Intel.
"""

import typer

# These are imported from the main, installed chimera-intel package

from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.ecosystem_intel import ecosystem_app


class EcosystemPlugin(ChimeraPlugin):
    """Ecosystem Intelligence plugin that provides analysis of a company's business ecosystem."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera ecosystem')

        return "ecosystem"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return ecosystem_app

    def initialize(self):
        """Initializes the Ecosystem Intelligence plugin."""
        pass
