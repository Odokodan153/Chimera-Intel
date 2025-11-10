"""
Channel & Acquisition Intelligence (CHANINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.channel_intel import app as channel_app


class ChannelIntelPlugin(ChimeraPlugin):
    """CHANINT plugin that provides channel and acquisition intelligence commands."""

    @property
    def name(self) -> str:
        """Returns the canonical name of the plugin."""
        return "chanint"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer application for this plugin's CLI commands."""
        return channel_app

    def initialize(self):
        """Initializes the CHANINT plugin."""
        # No special initialization needed for this plugin
        pass