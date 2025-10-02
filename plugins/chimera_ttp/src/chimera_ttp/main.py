"""
MITRE ATT&CK TTP Mapping Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.ttp_mapper import ttp_app


class TTPPlugin(ChimeraPlugin):
    """TTP plugin that provides CVE to MITRE ATT&CK mapping."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera ttp')

        return "ttp"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return ttp_app

    def initialize(self):
        """Initializes the TTP Mapping plugin."""
        pass
