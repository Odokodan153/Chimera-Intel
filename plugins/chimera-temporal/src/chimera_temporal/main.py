"""
Temporal Analysis Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.temporal_analyzer import temporal_app


class TemporalPlugin(ChimeraPlugin):
    """Temporal analysis plugin for tracking a company's shifting identity."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'analysis' group

        return "analysis"

    @property
    def app(self) -> typer.Typer:
        plugin_app = typer.Typer()
        plugin_app.add_typer(
            temporal_app,
            name="temporal",
            help="Analyzes historical web data to track changes over time.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Temporal Analysis plugin."""
        pass
