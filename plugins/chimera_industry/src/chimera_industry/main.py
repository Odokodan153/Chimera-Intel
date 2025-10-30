"""
Industry Intelligence Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.industry_intel import industry_intel_app


class IndustryIntelPlugin(ChimeraPlugin):
    """Industry Intelligence plugin for market analysis."""

    @property
    def name(self) -> str:
        return "industry"

    @property
    def app(self) -> typer.Typer:
        return industry_intel_app

    def initialize(self):
        """Initializes the Industry Intelligence plugin."""
        pass
