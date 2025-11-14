"""
Plugin registration file for the CCI module.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.cci import cci_app 

class ChannelIntelPlugin(ChimeraPlugin):
    """CHANINT plugin that provides channel and acquisition intelligence commands."""

    @property
    def name(self) -> str:
        """Returns the canonical name of the plugin."""
        return "CCI"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer application for this plugin's CLI commands."""
        return cci_app

    def initialize(self):
        """Initializes the CCI plugin."""
        # No special initialization needed for this plugin
        pass