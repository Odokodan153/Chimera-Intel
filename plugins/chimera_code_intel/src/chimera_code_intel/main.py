"""
Code Intelligence Plugin for Chimera Intel.
"""

import typer

# These are imported from the main, installed chimera-intel package

from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.code_intel import code_intel_app


class CodeIntelPlugin(ChimeraPlugin):
    """Code Intelligence plugin that provides repository analysis commands."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera code-intel')

        return "code-intel"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return code_intel_app

    def initialize(self):
        """Initializes the Code Intelligence plugin."""
        pass
