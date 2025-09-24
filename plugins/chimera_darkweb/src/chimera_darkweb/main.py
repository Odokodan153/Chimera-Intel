"""
Dark Web OSINT Plugin for Chimera Intel.
"""

import typer

# These are imported from the main, installed chimera-intel package

from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.dark_web_osint import dark_web_app


class DarkWebPlugin(ChimeraPlugin):
    """Dark Web OSINT plugin that provides dark web search commands."""

    @property
    def name(self) -> str:
        # This will be part of the 'defensive' command group

        return "defensive"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the dark_web_app onto
        # This is because a single Typer app can't be added to multiple parents

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            dark_web_app, name="darkweb", help="Searches the dark web for leaked data."
        )
        return plugin_app

    def initialize(self):
        """Initializes the Dark Web OSINT plugin."""
        pass
