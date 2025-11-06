"""
Technical Forensics Plugin for Chimera Intel.

This plugin provides advanced, heuristic-based technical forensic analysis
for images and videos, including lighting, perspective, and lip-sync checks.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.technical_forensics import cli_app as technical_forensics_app

class TechnicalForensicsPlugin(ChimeraPlugin):
    """
    Plugin wrapper for the Advanced Technical Forensics module.
    """

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera tech-forensics')
        """
        return "tech-forensics"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the Typer app instance in the core module
        """
        return technical_forensics_app

    def initialize(self):
        """Initializes the Technical Forensics plugin."""
        # No special initialization required for this plugin
        pass