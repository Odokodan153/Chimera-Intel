"""
Cyber Intelligence (CYBINT) Plugin for Chimera Intel.
"""

import typer

# These are imported from the main, installed chimera-intel package

from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.cybint import cybint_app
from chimera_intel.core.threat_hunter import threat_hunter_app


class CybintPlugin(ChimeraPlugin):
    """CYBINT plugin that provides attack surface and threat hunting commands."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera cybint')

        return "cybint"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return cybint_app

    def initialize(self):
        """Initializes the CYBINT plugin by adding its sub-commands."""
        # This is where we now register the sub-commands for cybint

        self.app.add_typer(
            threat_hunter_app,
            name="threat-hunt",
            help="Hunt for threat actor IOCs in logs.",
        )
