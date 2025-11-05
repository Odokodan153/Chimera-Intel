"""
Chimera Intel Plugin: Vector Search
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.vector_search import vector_app


class VectorSearchPlugin(ChimeraPlugin):
    """
    Registers the Vector Search (CLIP/FAISS)
    commands with the main Chimera CLI.
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "vector_search"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return vector_app

    def initialize(self):
        """A method to perform any setup for the plugin."""
        # No specific initialization needed for this plugin
        pass