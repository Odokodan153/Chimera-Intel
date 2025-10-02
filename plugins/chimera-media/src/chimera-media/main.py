"""
Audio-Visual Intelligence (IMINT/VIDINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.media_analyzer import media_app


class MediaPlugin(ChimeraPlugin):
    """IMINT/VIDINT plugin for media analysis."""

    @property
    def name(self) -> str:
        return "media"

    @property
    def app(self) -> typer.Typer:
        return media_app

    def initialize(self):
        """Initializes the Media Intelligence plugin."""
        pass
