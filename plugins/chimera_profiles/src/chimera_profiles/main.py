"""
Social Media Profile OSINT Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.social_osint import social_osint_app


class SocialOsintPlugin(ChimeraPlugin):
    """Social Media Profile OSINT plugin."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'scan' group

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the social_osint_app onto.

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            social_osint_app,
            name="profiles",
            help="Finds social media profiles by username.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Social Media Profile OSINT plugin."""
        pass
