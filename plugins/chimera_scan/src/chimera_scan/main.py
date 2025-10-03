"""
Plugin for active scanning and deep analysis in Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.scan import scan_app


class ScanPlugin(ChimeraPlugin):
    """Plugin for active scanning and deep analysis."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera scan')

        return "scan"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance defined in src/chimera_intel/core/scan.py

        return scan_app

    def initialize(self):
        """Initializes the Scan plugin."""
        pass
