"""
Digital Provenance Plugin for Chimera-Intel.
"""
import typer 
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.provenance_service import provenance_app, _check_dependencies
from chimera_intel.core.logger import logger, console

class ProvenancePlugin(ChimeraPlugin):
    """
    Registers the Digital Provenance module, providing commands to
    embed and verify signed, timestamped manifests in media.
    """

    @property
    def name(self) -> str:
        """The command name for this plugin."""
        return "provenance"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance."""
        return provenance_app

    def initialize(self):
        """Initializes the plugin."""
        # Check for core dependencies on load
        try:
            _check_dependencies()
            logger.info("Provenance plugin dependencies checked successfully.")
        except Exception:
             # Don't hard-fail, but log the critical error
            logger.critical("Provenance plugin initialization FAILED. Dependencies missing.")
            console.print("[bold red]Warning:[/bold red] 'provenance' plugin failed to load. "
                          "Please run: [cyan]pip install pillow stegano rfc3161-client cryptography[/cyan]")


# 4. Expose the plugin instance for the plugin manager
plugin = ProvenancePlugin()