"""
Radio Frequency (RF) Analysis (SIGINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.sigint import sigint_app


class SigintPlugin(ChimeraPlugin):
    """Radio Frequency (RF) Analysis (SIGINT) plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera sigint')

        return "sigint"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return sigint_app

    def initialize(self):
        """Initializes the SIGINT plugin."""
        pass
