"""
Social Media Content Analysis Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.social_analyzer import social_app


class SocialAnalyzerPlugin(ChimeraPlugin):
    """Social Media Content Analysis plugin."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'scan' group

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the social_app onto.

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            social_app,
            name="social",
            help="Analyzes content from a target's RSS feed.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Social Media Content Analysis plugin."""
        pass
