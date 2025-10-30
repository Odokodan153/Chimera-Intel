"""
Imagery Intelligence (IMINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.imint import imint_app


class ImintPlugin(ChimeraPlugin):
    """Imagery Intelligence (IMINT) plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera imint')

        return "imint"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return imint_app

    def initialize(self):
        """Initializes the IMINT plugin."""
        pass
