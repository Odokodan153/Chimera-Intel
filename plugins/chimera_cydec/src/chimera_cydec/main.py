# plugins/chimera_cydec/src/chimera_cydec/main.py
"""
Chimera Intel Plugin for CYDEC (Cyber Deception).

This plugin registers the 'cydec' command group, which provides
tools for active, AI-powered deception operations.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.cydec import cydec_app

class CydecPlugin(ChimeraPlugin):
    """
    A plugin to add AI-powered cyber deception (CYDEC) capabilities.
    """

    @property
    def name(self) -> str:
        """The name of the plugin."""
        return "cydec"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        # Return the app imported from the core module
        return cydec_app

    def initialize(self):
        """Initialize the plugin (no setup needed here)."""
        pass

# This is the required entry point for the plugin system
def create_plugin() -> ChimeraPlugin:
    """Plugin factory function."""
    return CydecPlugin()