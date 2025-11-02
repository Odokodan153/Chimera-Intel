"""
HUMINT - Leadership Profiler Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.leadership_profiler import leadership_profiler_app


class LeadershipProfilerPlugin(ChimeraPlugin):
    """HUMINT plugin that provides leadership profiling commands."""

    @property
    def name(self) -> str:
        """This will be part of the 'humint' command group."""
        return "humint"

    @property
    def app(self) -> typer.Typer:
        """
        We need a new Typer app to mount the leadership_profiler_app onto.
        """
        plugin_app = typer.Typer()
        plugin_app.add_typer(
            leadership_profiler_app,
            name="leadership",
            help="Deep-dive OSINT/HUMINT on key executives."
        )
        return plugin_app

    def initialize(self):
        """Initializes the Leadership Profiler plugin."""
        pass
