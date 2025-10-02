"""
Legal Intelligence (LEGINT) Plugin for Chimera Intel.
"""

import typer

# These are imported from the main, installed chimera-intel package

from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.legint import legint_app


class LegintPlugin(ChimeraPlugin):
    """LEGINT plugin that provides legal intelligence commands."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera legint')

        return "legint"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return legint_app

    def initialize(self):
        """Initializes the LEGINT plugin."""
        # No special initialization is needed for this simple plugin

        pass
