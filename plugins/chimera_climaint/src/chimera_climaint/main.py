"""
Climate Intelligence (CLIMAINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.climaint import climaint_app


class ClimaintPlugin(ChimeraPlugin):
    """Climate Intelligence (CLIMAINT) plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera climaint')
        return "climaint"

    @property
    def app(self) -> typer.Typer:
        # This points to the new Typer app instance
        return climaint_app

    def initialize(self):
        """Initializes the CLIMAINT plugin."""
        pass