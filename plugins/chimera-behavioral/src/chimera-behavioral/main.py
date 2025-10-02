# plugins/chimera_behavioral/src/chimera_behavioral/main.py

"""
Behavioral & Psychographic OSINT Plugin for Chimera Intel.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.behavioral_analyzer import behavioral_app


class BehavioralPlugin(ChimeraPlugin):
    """Behavioral & Psychographic OSINT plugin."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'analysis' group

        return "analysis"

    @property
    def app(self) -> typer.Typer:
        plugin_app = typer.Typer()
        plugin_app.add_typer(
            behavioral_app,
            name="behavioral",
            help="Analyzes corporate culture and psychographics.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Behavioral Analysis plugin."""
        pass
