"""
Money Laundering Intelligence (MLINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.mlint import mlint_app


class MlintPlugin(ChimeraPlugin):
    """MLINT plugin that provides money laundering intelligence commands."""

    @property
    def name(self) -> str:
        return "mlint"

    @property
    def app(self) -> typer.Typer:
        return mlint_app

    def initialize(self):
        """Initializes the MLINT plugin."""
        # No special initialization needed for this plugin
        pass