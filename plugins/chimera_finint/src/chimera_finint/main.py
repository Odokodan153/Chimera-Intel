"""
Financial Intelligence (FININT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.finint import finint_app  # We re-use the existing Typer app


class FinintPlugin(ChimeraPlugin):
    """FININT plugin that provides financial intelligence commands."""

    @property
    def name(self) -> str:
        return "finint"

    @property
    def app(self) -> typer.Typer:
        return finint_app

    def initialize(self):
        """Initializes the FININT plugin."""
        # No special initialization needed for this plugin

        pass
