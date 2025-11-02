import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.disinformation_analyzer import disinformation_app

class DisinformationPlugin(ChimeraPlugin):
    """
    Plugin for Disinformation and Synthetic Narrative Analysis.
    
    Provides tools to detect AI-generated prose and map
    coordinated information campaigns.
    """

    @property
    def name(self) -> str:
        return "Disinformation-Audit"

    @property
    def app(self) -> typer.Typer:
        return disinformation_app

    def initialize(self):
        """Initialize any required clients or settings."""
        pass
