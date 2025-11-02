"""
Vehicle (VIN) OSINT Plugin for Chimera Intel.
"""

import typer

# These are imported from the main, installed chimera-intel package
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.vehicle_osint import vehicle_osint_app


class VehiclePlugin(ChimeraPlugin):
    """Vehicle OSINT plugin that provides VIN lookup commands."""

    @property
    def name(self) -> str:
        # This will be part of the 'scan' command group, per the user table
        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the vehicle_osint_app onto
        plugin_app = typer.Typer()
        plugin_app.add_typer(
            vehicle_osint_app, 
            name="vehicle", 
            help="Looks up vehicle information from a VIN."
        )
        return plugin_app

    def initialize(self):
        """Initializes the Vehicle OSINT plugin."""
        pass