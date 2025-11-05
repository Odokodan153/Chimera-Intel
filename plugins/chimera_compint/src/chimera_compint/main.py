"""
Competitive Image Intelligence (COMPINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.competitive_imint import compint_app

class CompetitiveImintPlugin(ChimeraPlugin):
    """
    Plugin for high-value competitive image intelligence.
    
    Orchestrates modules for:
    - Product & ad creative analysis
    - Creative attribution (ad reuse)
    - Brand misuse & counterfeit detection
    - Defensive counter-disinformation
    - Securing images as legal evidence
    """

    @property
    def name(self) -> str:
        """This defines the top-level command name: 'chimera compint'"""
        return "compint"

    @property
    def app(self) -> typer.Typer:
        """This points to the Typer app instance in the core module."""
        return compint_app

    def initialize(self):
        """Initializes the COMPINT plugin."""
        # No initialization needed for this plugin
        pass
