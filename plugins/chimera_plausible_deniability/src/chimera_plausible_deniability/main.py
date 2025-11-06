"""
Chimera Intel Plugin: Plausible Deniability
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.plausible_deniability import pd_app


class PlausibleDeniabilityPlugin(ChimeraPlugin):
    """
    Registers the Plausible Deniability (PD) module for
    anonymizing and sharing reports.
    """

    @property
    def name(self) -> str:
        """The command name for this plugin."""
        return "pd"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance."""
        return pd_app

    def initialize(self):
        """Initializes the plugin."""
        pass