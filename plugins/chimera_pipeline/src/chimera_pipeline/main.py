"""
Chimera Intel Plugin: Data Pipeline
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.data_pipeline import pipeline_app


class DataPipelinePlugin(ChimeraPlugin):
    """
    Registers the Data Pipeline (ingest, store, index)
    commands with the main Chimera CLI.
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "pipeline"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return pipeline_app

    def initialize(self):
        """
        Initializes the plugin.
        Checks for Playwright browser binaries.
        """
        import subprocess
        from rich.console import Console
        console = Console()
        
        # Check if playwright browsers are installed
        try:
            subprocess.run(["playwright", "install"], check=True, capture_output=True)
            console.print("Playwright browsers are installed.", style="dim green")
        except FileNotFoundError:
            console.print("[bold yellow]Warning:[/bold yellow] 'playwright' command not found. Skipping browser check.", style="yellow")
        except subprocess.CalledProcessError:
            console.print("[bold red]Error:[/bold red] 'playwright install' failed. Dynamic scraping may not work.", style="red")