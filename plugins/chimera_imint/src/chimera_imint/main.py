"""
Image & Video Intelligence (IMINT/VIDINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.imint import imint_app


class ImintPlugin(ChimeraPlugin):
    """IMINT/VIDINT plugin for image and video analysis."""

    @property
    def name(self) -> str:
        return "imint"

    @property
    def app(self) -> typer.Typer:
        return imint_app

    def initialize(self):
        """Initializes the IMINT/VIDINT plugin."""
        pass
