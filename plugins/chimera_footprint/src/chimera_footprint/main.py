"""
Digital Footprint Scanning Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.footprint import footprint_app


class FootprintPlugin(ChimeraPlugin):
    """Digital Footprint plugin for WHOIS, DNS, and subdomain enumeration."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'scan' group

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the footprint_app onto.
        # This ensures the plugin is self-contained.

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            footprint_app,
            name="footprint",
            help="Gathers basic digital footprint (WHOIS, DNS, Subdomains).",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Digital Footprint plugin."""
        pass
