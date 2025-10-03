"""
Operational Technology (OT) & ICS/SCADA Intelligence Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.ot_intel import ot_intel_app


class OtIntelPlugin(ChimeraPlugin):
    """Operational Technology (OT) & ICS/SCADA Intelligence plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera ot-intel')

        return "ot-intel"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return ot_intel_app

    def initialize(self):
        """Initializes the OT Intelligence plugin."""
        pass
