"""
Maritime & Shipping Intelligence (MARINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.marint import marint_app


class MarintPlugin(ChimeraPlugin):
    """Maritime & Shipping Intelligence (MARINT) plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera marint')

        return "marint"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return marint_app

    def initialize(self):
        """Initializes the Maritime & Shipping Intelligence (MARINT) plugin."""
        pass
