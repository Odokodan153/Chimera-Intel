"""
Internal Analysis & Forensics Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.internal import internal_app


class InternalPlugin(ChimeraPlugin):
    """Internal Analysis & Forensics plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera internal')

        return "internal"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return internal_app

    def initialize(self):
        """Initializes the Internal Analysis & Forensics plugin."""
        pass
