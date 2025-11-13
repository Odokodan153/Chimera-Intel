"""
RADINT (Radar Intelligence) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.radint import radint_app


class RadintPlugin(ChimeraPlugin):
    """RADINT (SAR Analysis) plugin."""

    @property
    def name(self) -> str:
        """This defines the command name (e.g., 'chimera radint')"""
        return "radint"

    @property
    def app(self) -> typer.Typer:
        """This points to the existing Typer app instance in the core module"""
        return radint_app

    def initialize(self):
        """Initializes the RADINT plugin."""
        pass