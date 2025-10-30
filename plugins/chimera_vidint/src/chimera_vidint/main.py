"""
Video Intelligence (VIDINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.vidint import vidint_app


class VidintPlugin(ChimeraPlugin):
    """Video Intelligence (VIDINT) plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera vidint')

        return "vidint"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance defined in src/chimera_intel/core/vidint.py

        return vidint_app

    def initialize(self):
        """Initializes the VIDINT plugin."""
        pass
