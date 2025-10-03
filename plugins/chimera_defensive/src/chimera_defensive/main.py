"""
Defensive & Vulnerability Scanning Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.defensive import defensive_app
from chimera_intel.core.vulnerability_scanner import vulnerability_app
from chimera_intel.core.dark_web_osint import dark_web_app
from .dark_web_monitor import dark_web_monitor_app
from .page_monitor import page_monitor_app


class DefensivePlugin(ChimeraPlugin):
    """Defensive & Vulnerability Scanning plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera defensive')

        return "defensive"

    @property
    def app(self) -> typer.Typer:
        # We create a new Typer app here to register all the sub-commands

        defensive_group_app = typer.Typer(
            help="Run defensive and vulnerability scans on your own assets."
        )
        defensive_group_app.add_typer(
            defensive_app,
            name="checks",
            help="Run standard defensive checks (breaches, leaks, etc.).",
        )
        defensive_group_app.add_typer(
            vulnerability_app,
            name="vuln",
            help="Run vulnerability scans on discovered assets.",
        )
        defensive_group_app.add_typer(
            dark_web_app, name="darkweb", help="Searches the dark web for leaked data."
        )
        defensive_app.add_typer(
            dark_web_monitor_app,
            name="dark-monitor",
            help="Continuously monitors dark web sites for keyword mentions.",
        )
        defensive_app.add_typer(
            page_monitor_app,
            name="page-monitor",
            help="Monitors specific web pages for visual and textual changes.",
        )
        return defensive_group_app

    def initialize(self):
        """Initializes the Defensive & Vulnerability Scanning plugin."""
        pass
