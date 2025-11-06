# Chimera-Intel/plugins/chimera_analyst_opsec/src/chimera_analyst_opsec/main.py
"""
Chimera Intel Plugin: Analyst Operational Security
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.analyst_opsec import analyst_opsec_app


class AnalystOpsecPlugin(ChimeraPlugin):
    """
    Registers the Analyst OPSEC module, providing tools for
    managing analyst credentials and session security.
    """

    @property
    def name(self) -> str:
        """The command name for this plugin."""
        return "opsec-admin"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance."""
        return analyst_opsec_app

    def initialize(self):
        """Initializes the plugin."""
        pass