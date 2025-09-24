# plugins/chimera_podcast/src/chimera_podcast/main.py

"""
Podcast OSINT Plugin for Chimera Intel.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.podcast_osint import podcast_app


class PodcastPlugin(ChimeraPlugin):
    """Podcast OSINT plugin for analyzing podcast feeds and episodes."""

    @property
    def name(self) -> str:
        return "scan"

    @property
    def app(self) -> typer.Typer:
        plugin_app = typer.Typer()
        plugin_app.add_typer(
            podcast_app,
            name="podcast",
            help="Gathers intelligence from podcast feeds and episodes.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Podcast OSINT plugin."""
        pass
