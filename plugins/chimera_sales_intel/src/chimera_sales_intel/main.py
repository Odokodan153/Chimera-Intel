"""
Sales & Business Intent Intelligence (SALINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.sales_intel import app as sales_intel_app


class SalesIntelPlugin(ChimeraPlugin):
    """Sales & Intent Intelligence (SALINT) plugin."""

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera salint')
        """
        return "salint"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the Typer app instance in the core module
        """
        return sales_intel_app

    def initialize(self):
        """Initializes the Sales Intel plugin."""
        # No initialization needed for this module
        pass