"""
Human Intelligence (HUMINT) Management Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.humint import humint_app


class HumintPlugin(ChimeraPlugin):
    """Human Intelligence (HUMINT) Management plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera humint')

        return "humint"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module

        return humint_app

    def initialize(self):
        """Initializes the HUMINT plugin."""
        pass
