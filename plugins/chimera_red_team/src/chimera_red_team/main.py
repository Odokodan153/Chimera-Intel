"""
Adversarial Simulation & Strategy Validation Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.red_team import red_team_app


class RedTeamPlugin(ChimeraPlugin):
    """Adversarial Simulation & Strategy Validation Engine plugin."""

    @property
    def name(self) -> str:
        return "red-team"

    @property
    def app(self) -> typer.Typer:
        return red_team_app

    def initialize(self):
        pass
