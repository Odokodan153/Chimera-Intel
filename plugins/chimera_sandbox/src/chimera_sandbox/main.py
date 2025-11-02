"""
Malware Behavior Sandbox Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.malware_sandbox import sandbox_app


class SandboxPlugin(ChimeraPlugin):
    """Malware Behavior Sandbox plugin."""

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera sandbox')
        """
        return "sandbox"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the Typer app instance in the core module
        """
        return sandbox_app

    def initialize(self):
        """Initializes the Sandbox plugin."""
        pass