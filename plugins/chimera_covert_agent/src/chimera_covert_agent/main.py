from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.covert_intel_agent import covert_app
import typer

class CovertAgentPlugin(ChimeraPlugin):
    """
    Plugin for the AI-Driven Covert Intelligence Agent.
    """
    
    def get_name(self) -> str:
        return "Covert Agent"

    def register_cli_commands(self) -> typer.Typer:
        """
        Registers the 'covert' command group with the main CLI.
        """
        return covert_app

# The entry point for the plugin manager
plugin = CovertAgentPlugin()