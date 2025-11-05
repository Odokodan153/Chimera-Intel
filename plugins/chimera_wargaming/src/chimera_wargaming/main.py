"""
Massive Scenario & Wargaming Engine Plugin for Chimera Intel.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.wargaming_engine import plugin as wargaming_app

class WargamingPlugin(ChimeraPlugin):
    """Massive Scenario & Wargaming Engine plugin."""

    @property
    def name(self) -> str:
        """This defines the command name (e.g., 'chimera wargaming')"""
        return "wargaming"

    @property
    def app(self) -> typer.Typer:
        """This points to the existing Typer app instance in the core module"""
        return wargaming_app

    def initialize(self):
        """Initializes the Wargaming plugin."""
        pass

# Instantiate the plugin for the entry point
# The pyproject.toml's entry point "chimera_wargaming.main:plugin"
# will point to this instance.
plugin = WargamingPlugin()