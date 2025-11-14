"""
Plugin to register the Key Opinion Leader (KOL) Analyzer module.
"""
import typer
from chimera_intel.core.plugin_interface import Plugin
from chimera_intel.core.kol_analyzer import kol_analyzer_app

class KolAnalyzerPlugin(Plugin):
    """A plugin to add the KOL Analyzer CLI commands."""

    def get_name(self) -> str:
        return "KOLAnalyzer"

    def get_description(self) -> str:
        return "Adds CLI commands for identifying Key Opinion Leaders (KOLs)."

    def register_cli_commands(self) -> typer.Typer:
        """Registers the 'kol' command group."""
        return kol_analyzer_app

    def register_fastapi_routers(self) -> list:
        """No web routers for this plugin."""
        return []

def create_plugin() -> Plugin:
    return KolAnalyzerPlugin()