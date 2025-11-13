"""
Policy & Regulatory Intelligence (POLINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.polint import polint_app  # Import the app from the core module

class PolIntPlugin(ChimeraPlugin):
    """
    POLINT plugin for proactive policy and regulation tracking.
    """

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return "polint"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer application for this plugin."""
        return polint_app

    def initialize(self):
        """Initialize any required resources for the POLINT plugin."""
        # Initialization logic can be added here if needed,
        # e.g., setting up specific API clients or database connections
        # not handled by the core.
        pass