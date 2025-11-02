"""
Supply Chain Risk AI Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.supply_chain_risk import supply_chain_app


class SupplyChainPlugin(ChimeraPlugin):
    """Supply Chain Risk AI plugin."""

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera supply')
        """
        return "supply"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the Typer app instance in the core module
        """
        return supply_chain_app

    def initialize(self):
        """Initializes the Supply Chain plugin."""
        pass