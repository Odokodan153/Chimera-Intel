"""
Blockchain OSINT Plugin for Chimera Intel.
"""

import typer

# These are imported from the main, installed chimera-intel package

from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.blockchain_osint import blockchain_app


class BlockchainPlugin(ChimeraPlugin):
    """Blockchain OSINT plugin that provides wallet analysis commands."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera blockchain')

        return "blockchain"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return blockchain_app

    def initialize(self):
        """Initializes the Blockchain OSINT plugin."""
        pass
