"""
Weak Signal Amplification (WSA) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.weak_signal_analyzer import wsa_app


class WsaPlugin(ChimeraPlugin):
    """Weak Signal Amplification plugin."""

    @property
    def name(self) -> str:
        return "analysis"

    @property
    def app(self) -> typer.Typer:
        plugin_app = typer.Typer()
        plugin_app.add_typer(
            wsa_app,
            name="wsa",
            help="Amplifies weak signals using evidence theory.",
        )
        return plugin_app

    def initialize(self):
        """Initializes the WSA plugin."""
        pass
