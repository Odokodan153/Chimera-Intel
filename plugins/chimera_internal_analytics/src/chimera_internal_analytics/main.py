"""
Internal Analytics (INTA) Simulation Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.internal_analytics import app as internal_analytics_app


class InternalAnalyticsPlugin(ChimeraPlugin):
    """Internal Analytics (INTA) simulation plugin."""

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera inta')
        """
        return "inta"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the Typer app instance in the core module
        """
        return internal_analytics_app

    def initialize(self):
        """Initializes the Internal Analytics plugin."""
        # No initialization needed
        pass