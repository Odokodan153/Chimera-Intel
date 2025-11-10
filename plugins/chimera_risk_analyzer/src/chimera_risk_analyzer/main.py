import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.holistic_risk_analyzer import risk_app

class HolisticRiskPlugin(ChimeraPlugin):
    """
    Plugin for Holistic Risk Analysis.
    """

    @property
    def name(self) -> str:
        return "Risk Analyzer"

    @property
    def app(self) -> typer.Typer:
        return risk_app

    def initialize(self):
        """Initialize the risk analyzer plugin."""
        pass

# This function is the required entry point for the plugin manager.
def load_plugin() -> ChimeraPlugin:
    return HolisticRiskPlugin()