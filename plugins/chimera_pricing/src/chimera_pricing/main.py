"""
Pricing & Promotion Intelligence (PRICEINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.pricing_intel import app as pricing_app


class PricingIntelPlugin(ChimeraPlugin):
    """PRICEINT plugin that provides pricing and promotion intelligence commands."""

    @property
    def name(self) -> str:
        """Returns the canonical name of the plugin."""
        return "priceint"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer application for this plugin's CLI commands."""
        return pricing_app

    def initialize(self):
        """Initializes the PRICEINT plugin."""
        # No special initialization needed for this plugin
        pass