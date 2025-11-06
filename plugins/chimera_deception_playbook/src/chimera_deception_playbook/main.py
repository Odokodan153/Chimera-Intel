"""
Chimera Intel Plugin: Deception Response Playbook
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.deception_playbook import playbook_app

class DeceptionPlaybookPlugin(ChimeraPlugin):
    """
    A plugin to add the end-to-end Deception IR Playbook.
    """

    @property
    def name(self) -> str:
        """The name of the plugin."""
        return "Deception Playbook"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return playbook_app

    def initialize(self):
        """Initialize the plugin (no setup needed here)."""
        pass

# This is the required entry point for the plugin system
def create_plugin() -> ChimeraPlugin:
    """Plugin factory function."""
    return DeceptionPlaybookPlugin()