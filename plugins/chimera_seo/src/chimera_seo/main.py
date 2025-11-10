"""
Plugin definition for SEO & Content Intelligence.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.seo_intel import seo_intel_app

class SeoIntelPlugin(ChimeraPlugin):
    """
    A plugin for analyzing SEO keywords, backlinks, and content strategy.
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "seo"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return seo_intel_app

    def initialize(self):
        """Perform any setup for the plugin."""
        pass