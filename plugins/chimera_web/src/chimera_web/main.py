"""
Web Analysis Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.web_analyzer import web_app


class WebAppPlugin(ChimeraPlugin):
    """Web Analysis plugin for technology stack and traffic analysis."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'scan' group

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the web_app onto.
        # This ensures the plugin is self-contained.

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            web_app,
            name="web",
            help="Analyzes web-specific data (Tech Stack, Traffic).",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Web Analysis plugin."""
        pass
