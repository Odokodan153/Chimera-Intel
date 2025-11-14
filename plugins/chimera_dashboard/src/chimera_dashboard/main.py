"""
Plugin for the Interactive BI Dashboard.
"""
from chimera_intel.core.plugin_interface import Plugin
from chimera_intel.core.dashboard_router import (
    dashboard_router, 
    dashboard_app,
)
from fastapi import FastAPI
import typer


class DashboardPlugin(Plugin):
    """A plugin to add an interactive BI dashboard to the webapp."""

    def get_name(self) -> str:
        return "Dashboard"

    def get_description(self) -> str:
        return "Adds an interactive BI dashboard to the web UI."

    def register_cli_commands(self) -> typer.Typer:
        """Registers the 'dashboard' CLI command group."""
        return dashboard_app

    def register_fastapi_routers(self) -> list:
        """Registers the /dashboard router."""
        return [(dashboard_router, "/dashboard")]


def create_plugin() -> Plugin:
    return DashboardPlugin()