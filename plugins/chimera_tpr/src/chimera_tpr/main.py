"""
Third-Party Risk Management (TPRM) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.tpr_engine import tpr_app


class TPRMPlugin(ChimeraPlugin):
    """Third-Party Risk Management plugin for comprehensive scans."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera tpr-scan')

        return "tpr-scan"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return tpr_app

    def initialize(self):
        """Initializes the TPRM plugin."""
        pass
