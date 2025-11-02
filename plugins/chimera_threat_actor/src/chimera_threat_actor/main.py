"""
Threat Actor Profiling Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.threat_actor_intel import threat_actor_app


class ThreatActorPlugin(ChimeraPlugin):
    """Threat Actor Profiling plugin."""

    @property
    def name(self) -> str:
        """
        This defines the top-level command name (e.g., 'chimera actor')
        """
        return "actor"

    @property
    def app(self) -> typer.Typer:
        """
        This points to the Typer app instance in the core module
        """
        return threat_actor_app

    def initialize(self):
        """Initializes the Threat Actor plugin."""
        pass