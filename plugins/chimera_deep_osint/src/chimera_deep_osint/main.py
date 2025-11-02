# plugins/chimera_deep_osint/src/chimera_deep_osint/main.py

import typer
import logging
from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the pre-assembled Typer app from the new CLI module
from chimera_intel.core.deep_osint_cli import deep_osint_app


class DeepOsintPlugin(ChimeraPlugin):
    """
    Plugin for Deep OSINT & Data Enrichment.
    Provides commands for Dark Social, IoT, and Graph Analysis.
    """

    @property
    def name(self) -> str:
        # This will create a new top-level command: `chimera-intel deep-osint`
        return "deep-osint"

    @property
    def app(self) -> typer.Typer:
        # Return the pre-built Typer app imported from the core module
        return deep_osint_app

    def initialize(self):
        """Initializes the Deep OSINT plugin."""
        logging.info("Chimera Deep OSINT plugin initialized.")