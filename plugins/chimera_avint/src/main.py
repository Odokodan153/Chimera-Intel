"""
Aviation Intelligence (AVINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.avint import avint_app


class AvintPlugin(ChimeraPlugin):
    """AVINT plugin for tracking and analyzing aviation data."""

    @property
    def name(self) -> str:
        return "avint"

    @property
    def app(self) -> typer.Typer:
        return avint_app

    def initialize(self):
        """Initializes the AVINT plugin."""
        pass
