"""
Moving Target Intelligence (MOVINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.moving_target import moving_target_app


class MovingTargetPlugin(ChimeraPlugin):
    """MOVINT plugin for fusing AVINT, MARINT, and Social OSINT."""

    @property
    def name(self) -> str:
        return "movint"

    @property
    def app(self) -> typer.Typer:
        return moving_target_app

    def initialize(self):
        """Initialize any required resources for the MOVINT plugin."""
        pass