"""
Deception & Honeypot Operations Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.deception import deception_app


class DeceptionPlugin(ChimeraPlugin):
    """Deception & Honeypot Operations plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera deception')
        return "deception"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return deception_app

    def initialize(self):
        """Initializes the Deception plugin."""
        pass