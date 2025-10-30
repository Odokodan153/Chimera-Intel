"""
Automated Response & Counter-Offensive Operations Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.response import response_app


class ResponsePlugin(ChimeraPlugin):
    """Automated Response & Counter-Offensive Operations plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera response')
        return "response"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return response_app

    def initialize(self):
        """Initializes the Response plugin."""
        pass
