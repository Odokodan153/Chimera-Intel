"""
Chimera Intel Plugin: Threat Actor Emulation Lab
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.emulation_lab import lab_app


class EmulationLabPlugin(ChimeraPlugin):
    """
    Registers the Emulation Lab module for provisioning and
    managing sandboxed test environments.
    """

    @property
    def name(self) -> str:
        """The command name for this plugin."""
        return "lab"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance."""
        return lab_app

    def initialize(self):
        """Initializes the plugin."""
        pass