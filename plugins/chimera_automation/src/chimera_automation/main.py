"""
Automation & Enrichment Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.automation import automation_app, connect_app


class AutomationPlugin(ChimeraPlugin):
    """Automation & Enrichment plugin for Chimera Intel."""

    @property
    def name(self) -> str:
        # This plugin will register multiple top-level commands,
        # so we can just give it a logical name.

        return "automation"

    @property
    def app(self) -> typer.Typer:
        # We need a new Typer app to mount the command groups onto

        plugin_app = typer.Typer()
        plugin_app.add_typer(
            automation_app,
            name="auto",
            help="Run automation, enrichment, and advanced analysis tasks.",
        )
        plugin_app.add_typer(
            connect_app,
            name="connect",
            help="Integrate and orchestrate with external security tools.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the Automation & Enrichment plugin."""
        pass
