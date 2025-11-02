import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.pastebin_monitor import pastebin_app

class PastebinMonitorPlugin(ChimeraPlugin):
    """
    Plugin for real-time monitoring of paste sites.
    
    Detects accidental leaks of secrets, configurations, or credentials
    from sites like Pastebin, GitHub Gist, etc.
    """

    @property
    def name(self) -> str:
        return "Pastebin-Monitor"

    @property
    def app(self) -> typer.Typer:
        return pastebin_app

    def initialize(self):
        """Initialize any required clients or settings."""
        pass
