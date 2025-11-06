"""
Plugin definition for the Ensemble Detector module.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.ensemble_detector import ensemble_app


class EnsembleDetectorPlugin(ChimeraPlugin):
    """
    Integrates the Ensemble ML Detector module into the
    Chimera Intel plugin system.
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "ensemble"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return ensemble_app

    def initialize(self):
        """A method to perform any setup for the plugin."""
        # The ensemble_app's callback() already handles model loading.
        print("Ensemble Detector plugin initialized.")