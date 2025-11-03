"""
Plugin for 3D Knowledge Graph visualization.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.grapher_3d import graph_3d_app

class Graph3DPlugin(ChimeraPlugin):
    """Plugin for 3D interactive knowledge graphs using Plotly."""

    @property
    def name(self) -> str:
        # Give it a new name to avoid conflict with the 2D 'graph' plugin
        return "graph-3d" 

    @property
    def app(self) -> typer.Typer:
        return graph_3d_app

    def initialize(self):
        """Check for plotly dependency."""
        try:
            import plotly
        except ImportError:
            print("ERROR: 'plotly' library not found. Please run: pip install plotly")
            raise