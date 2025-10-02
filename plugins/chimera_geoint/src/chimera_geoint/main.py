"""
Geopolitical Intelligence (GEOINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.geoint import geoint_app


class GeointPlugin(ChimeraPlugin):
    """GEOINT plugin for assessing geopolitical risks."""

    @property
    def name(self) -> str:
        return "geoint"

    @property
    def app(self) -> typer.Typer:
        return geoint_app

    def initialize(self):
        pass
