"""
Business Intelligence Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.business_intel import business_app


class BusinessIntelPlugin(ChimeraPlugin):
    """Business Intelligence plugin for financials, news, and patents."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'scan' group

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the business_app onto.

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            business_app,
            name="business",
            help="Gathers business intelligence (Financials, News, Patents).",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Business Intelligence plugin."""
        pass
