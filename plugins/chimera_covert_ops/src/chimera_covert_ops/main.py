"""
Covert Digital Ops Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.covert_ops import covert_ops_app


class CovertOpsPlugin(ChimeraPlugin):
    """Covert Digital Operations plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera covert-ops')
        return "covert-ops"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module
        return covert_ops_app

    def initialize(self):
        """Initializes the Covert Ops plugin."""
        pass