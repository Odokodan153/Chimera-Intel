"""
Cloud OSINT Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.cloud_osint import cloud_osint_app


class CloudOsintPlugin(ChimeraPlugin):
    """Cloud OSINT plugin for finding exposed cloud storage assets."""

    @property
    def name(self) -> str:
        # This plugin's commands should be under the 'scan' group

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the cloud_osint_app onto.

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            cloud_osint_app,
            name="cloud",
            help="Scans for exposed cloud assets like S3 buckets.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Cloud OSINT plugin."""
        pass
