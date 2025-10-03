"""
Software Supply Chain Security (SCAINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.scaint import scaint_app


class ScaintPlugin(ChimeraPlugin):
    """Software Supply Chain Security (SCAINT) plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera scaint')

        return "scaint"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return scaint_app

    def initialize(self):
        """Initializes the SCAINT plugin."""
        pass
