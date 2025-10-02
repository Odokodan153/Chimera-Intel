"""
Corporate Records & Due Diligence Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.corporate_records import corporate_records_app


class CorporateRecordsPlugin(ChimeraPlugin):
    """Corporate Records plugin for due diligence checks."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera corporate-records')
        return "corporate-records"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module
        return corporate_records_app

    def initialize(self):
        """Initializes the Corporate Records plugin."""
        pass
