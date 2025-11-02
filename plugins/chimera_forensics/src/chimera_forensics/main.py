"""
Plugin definition for the Media Forensics module.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.media_forensics import forensics_app


class MediaForensicsPlugin(ChimeraPlugin):
    """
    Integrates the Deepfake & Photoshop Forensics module into the
    Chimera Intel plugin system.
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "forensics"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return forensics_app

    def initialize(self):
        """A method to perform any setup for the plugin."""
        print("Media Forensics plugin initialized.")