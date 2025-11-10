import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.entity_resolver import entity_app

class EntityResolverPlugin(ChimeraPlugin):
    """
    Plugin for Entity Resolution and Relationship Extraction.
    """

    @property
    def name(self) -> str:
        return "Entity Resolver"

    @property
    def app(self) -> typer.Typer:
        return entity_app

    def initialize(self):
        """Initialize the entity resolver plugin."""
        pass

# This function is the required entry point for the plugin manager.
def load_plugin() -> ChimeraPlugin:
    return EntityResolverPlugin()