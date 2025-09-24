"""
Mobile Application Intelligence (APPINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.appint import appint_app


class AppintPlugin(ChimeraPlugin):
    """APPINT plugin for mobile application analysis."""

    @property
    def name(self) -> str:
        return "appint"

    @property
    def app(self) -> typer.Typer:
        return appint_app

    def initialize(self):
        """Initializes the APPINT plugin."""
        pass
