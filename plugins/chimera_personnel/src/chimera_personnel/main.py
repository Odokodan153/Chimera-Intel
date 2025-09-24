"""
Personnel OSINT Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.personnel_osint import personnel_osint_app


class PersonnelOsintPlugin(ChimeraPlugin):
    """Personnel OSINT plugin for finding public employee email addresses."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'scan' group

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the personnel_osint_app onto.

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            personnel_osint_app,
            name="personnel",
            help="Gathers intelligence on company employees.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Personnel OSINT plugin."""
        pass
