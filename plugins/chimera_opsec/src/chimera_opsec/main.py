"""
Operational Security (OPSEC) Analysis Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.opsec_analyzer import opsec_app


class OpsecPlugin(ChimeraPlugin):
    """OPSEC plugin for correlating data to find security weaknesses."""

    @property
    def name(self) -> str:
        # This adds the 'opsec' command to the 'analysis' group

        return "analysis"

    @property
    def app(self) -> typer.Typer:
        plugin_app = typer.Typer()
        plugin_app.add_typer(
            opsec_app,
            name="opsec",
            help="Correlates scan data to find OPSEC weaknesses.",
        )
        return plugin_app

    def initialize(self):
        pass
