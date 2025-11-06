"""
Plugin registration for the Source Triage module.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.source_triage import triage_app


class SourceTriagePlugin(ChimeraPlugin):
    """
    Plugin for source triage and URL OSINT using Playwright.
    """

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera source-triage')
        """
        return "source-triage"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the Typer app instance in the core module
        """
        return triage_app

    def initialize(self):
        """Initializes the Source Triage plugin."""
        pass