"""
Chimera IMINT Ingestion Plugin

This plugin wraps the core IMINT ingestion pipeline functionality and exposes 
it to the main Chimera CLI under the 'imint' command.
"""

import typer
import os
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.imint_ingestion import imint_ingestion_app

# This is the main Typer app for this plugin
app = typer.Typer(
    name="imint",
    help="Image Intelligence (IMINT) & Ingestion Toolkit.",
)

# Add the commands from the core module
app.add_typer(
    imint_ingestion_app, 
    name="ingest",
    help="Image ingestion pipelines (from URL, search, etc.)"
)

# --- Plugin Class ---

class ImintIngestionPlugin(ChimeraPlugin):
    """
    Plugin for ingesting and processing images (IMINT).
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "IMINT Ingestion"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return app

    def initialize(self):
        """A method to perform any setup for the plugin."""
        # This message will print when the main Chimera CLI loads
        pass

