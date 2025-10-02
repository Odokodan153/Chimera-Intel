import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.graph_analyzer import graph_app


class GraphPlugin(ChimeraPlugin):
    """Graph analysis and visualization plugin."""

    @property
    def name(self) -> str:
        return "graph"

    @property
    def app(self) -> typer.Typer:
        return graph_app

    def initialize(self):
        """Initializes the Graph plugin."""
        pass
