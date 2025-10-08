import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core import risk_assessment

class RiskAssessmentPlugin(ChimeraPlugin):
    """
    Risk Assessment plugin.
    Provides tools to conduct and manage risk assessments.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera risk'."""
        return "risk"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'risk' command."""
        return risk_assessment.app

    def initialize(self):
        """Initializes the Risk Assessment plugin."""
        pass

# The plugin manager will discover and instantiate this class
plugin = RiskAssessmentPlugin()