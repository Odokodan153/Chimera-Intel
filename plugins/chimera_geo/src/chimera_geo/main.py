"""
Geolocation OSINT Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.geo_osint import geo_osint_app


class GeoOsintPlugin(ChimeraPlugin):
    """Geolocation OSINT plugin for geolocating IP addresses."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'scan' group

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the geo_osint_app onto.

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            geo_osint_app,
            name="geo",
            help="Retrieves geolocation information for IP addresses.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Geolocation OSINT plugin."""
        pass
