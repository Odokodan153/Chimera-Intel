"""
Plugin for Cryptocurrency Transaction Tracing.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.blockchain_tracer import tracer_app

class CryptoTracePlugin(ChimeraPlugin):
    """Plugin for tracing and visualizing crypto transactions."""

    @property
    def name(self) -> str:
        # Give it a new name to distinguish from 'crypto' (price) plugin
        return "crypto-trace" 

    @property
    def app(self) -> typer.Typer:
        return tracer_app

    def initialize(self):
        """Check for pyvis dependency."""
        try:
            import pyvis
        except ImportError:
            print("ERROR: 'pyvis' library not found. Please run: pip install pyvis")
            raise