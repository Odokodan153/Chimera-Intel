"""
Plugin for managing a human review queue for sensitive actions.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.human_review_service import review_app

class HumanReviewPlugin(ChimeraPlugin):
    
    @property
    def name(self) -> str:
        return "review"

    @property
    def app(self) -> typer.Typer:
        """
        Returns the Typer application for the human review service.
        """
        return review_app

    def initialize(self):
        return "Approve or deny sensitive actions pending review."