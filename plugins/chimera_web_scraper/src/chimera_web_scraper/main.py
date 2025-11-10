"""
(NEW) Active Web Scraper Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.web_scraper import web_scraper_app


class WebScraperPlugin(ChimeraPlugin):
    """(NEW) Active Web Scraper plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name
        # e.g., 'chimera web-scraper'
        return "web-scraper"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return web_scraper_app

    def initialize(self):
        """Initializes the plugin."""
        pass