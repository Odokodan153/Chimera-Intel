"""
Plugin for Global Keyword Monitoring.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.global_monitor import global_monitor_app

class GlobalMonitorPlugin(ChimeraPlugin):
    """Plugin for continuous keyword monitoring (sanctions, VIPs, etc.)."""

    @property
    def name(self) -> str:
        return "global-mon"

    @property
    def app(self) -> typer.Typer:
        return global_monitor_app

    def initialize(self):
        """Check for dependencies (google_search)."""
        pass # Dependencies are core