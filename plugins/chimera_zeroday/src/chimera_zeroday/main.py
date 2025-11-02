"""
Zero-Day Tracking Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.zero_day_tracking import zeroday_app


class ZeroDayPlugin(ChimeraPlugin):
    """Zero-Day Tracking plugin."""

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera zeroday')
        """
        return "zeroday"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the Typer app instance in the core module
        """
        return zeroday_app

    def initialize(self):
        """Initializes the Zero-Day Tracking plugin."""
        pass