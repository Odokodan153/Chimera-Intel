"""
Covert Financial Tracking (CFT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin

# We import the Typer app from the core module
from chimera_intel.core.covert_financial_tracking import cft_app


class CovertFinancialTrackingPlugin(ChimeraPlugin):
    """
    Covert Financial Tracking plugin.
    
    This plugin links the 'cft_app' from the core library
    to the main Chimera CLI.
    """

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera cft')
        """
        return "cft"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the existing Typer app instance in the core module
        """
        return cft_app

    def initialize(self):
        """Initializes the Covert Financial Tracking plugin."""
        # No special initialization needed for this plugin pattern
        pass