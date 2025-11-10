"""
Plugin to load the Strategic Analytics & KPI module.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the Typer app from the new core module
from chimera_intel.core.strategic_analytics import app as strategic_analytics_app


class StrategicAnalyticsPlugin(ChimeraPlugin):
    """
    Plugin for Strategic Intelligence & KPI Reporting.
    
    This plugin activates the 'strategy' command, which provides
    reports on KPIs (Coverage, Freshness, etc.) by aggregating
    data from other modules, as per the platform design notes.
    """

    @property
    def name(self) -> str:
        """This defines the top-level command name: 'chimera strategy'"""
        return "strategy"

    @property
    def app(self) -> typer.Typer:
        """This points to the Typer app instance in the core module."""
        return strategic_analytics_app

    def initialize(self):
        """Initializes the plugin."""
        # No complex initialization needed for this module
        pass