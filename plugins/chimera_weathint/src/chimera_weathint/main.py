"""
Weather & Environmental Intelligence (WEATHINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.weathint import weathint_app


class WeathintPlugin(ChimeraPlugin):
    """Weather & Environmental Intelligence (WEATHINT) plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera weathint')

        return "weathint"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module

        return weathint_app

    def initialize(self):
        """Initializes the WEATHINT plugin."""
        pass
