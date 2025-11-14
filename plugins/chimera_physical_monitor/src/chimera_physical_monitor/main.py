"""
Physical Location Monitor (GEOINT/IMINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.physical_monitor import phys_mon_app


class PhysicalMonitorPlugin(ChimeraPlugin):
    """Physical CI monitoring plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera phys-mon')
        return "phys-mon"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in our new module
        return phys_mon_app

    def initialize(self):
        """Initializes the plugin."""
        pass