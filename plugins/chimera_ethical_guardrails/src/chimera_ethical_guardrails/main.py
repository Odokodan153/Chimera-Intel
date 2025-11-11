"""Ethical Policy Engine Plugin for Chimera-Intel."""

import console
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.policy_engine import policy_app
class PolicyEnginePlugin(ChimeraPlugin):
    """
    Registers the ethical policy engine as a plugin.
    """
    @property
    def name(self) -> str:
        return "policy"

    @property
    def app(self) -> typer.Typer:
        return policy_app

    def initialize(self):
        console.print("[cyan]Policy Engine plugin loaded (Req 9).[/cyan]")

# Expose the plugin instance
plugin = PolicyEnginePlugin()