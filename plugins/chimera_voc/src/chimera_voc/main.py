"""
Plugin definition for Voice of Customer (VoC) Intelligence.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.voc_intel import voc_intel_app
  
class VoCIntelPlugin(ChimeraPlugin):
    """
    A plugin for analyzing customer reviews for sentiment, topics,
    and actionable insights.
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "voc"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return voc_intel_app

    def initialize(self):
        """Perform any setup for the plugin."""
        pass