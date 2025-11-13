import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.mdm_engine import (
    mdm_app,
    schedule_mdm_engine,
)
from src.chimera_intel.core.utils import console


class MDMEnginePlugin(ChimeraPlugin):
    """
    Plugin for the Master Data Management (MDM) Engine.
    Provides CLI commands and schedules the background deduplication service.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera mdm-engine'."""
        return "mdm-engine"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer app for the 'mdm-engine' command group."""
        return mdm_app

    def initialize(self):
        """
        Initializes the MDM plugin and schedules the background
        MDM cycle to run daily at 02:00 AM.
        """
        try:
            console.print(
                "[MDM Plugin] Initializing and scheduling daily cycle (02:00 AM)..."
            )
            # Default schedule: 02:00 AM every day
            schedule_mdm_engine(cron_schedule="0 2 * * *")
        except Exception as e:
            console.print(
                f"[bold red][MDM Plugin] Error during initialization:[/bold red] {e}"
            )


# The plugin manager will discover and instantiate this class
plugin = MDMEnginePlugin()