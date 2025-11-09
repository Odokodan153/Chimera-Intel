# plugins/chimera_market_demand/src/chimera_market_demand/main.py

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.market_demand_intel import market_demand_app

class MarketDemandPlugin(ChimeraPlugin):
    """
    Plugin for Market & Demand Intelligence.
    
    Provides commands for:
    - TAM/SAM/SOM Estimation
    - Demand Trend Tracking
    - Product Category Discovery
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "market_demand"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return market_demand_app

    def initialize(self):
        """A method to perform any setup for the plugin."""
        # No specific initialization needed for this plugin
        pass

# This function is the entry point for the plugin manager
def get_plugin() -> ChimeraPlugin:
    return MarketDemandPlugin()