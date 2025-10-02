"""
Social Media Monitoring Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.social_media_monitor import social_media_app


class SocialMediaMonitorPlugin(ChimeraPlugin):
    """Social media monitoring plugin for real-time data collection."""

    @property
    def name(self) -> str:
        return "social-media"

    @property
    def app(self) -> typer.Typer:
        return social_media_app

    def initialize(self):
        """Initializes the Social Media Monitoring plugin."""
        pass