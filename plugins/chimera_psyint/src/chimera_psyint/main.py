# plugins/chimera_psyint/src/chimera_psyint/main.py

"""
Plugin registration for the Active PSYINT (psyint) module.
Conforms to the ChimeraPlugin class-based interface.
"""

import typer
import logging
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.psyint import psyint_app, register_psyint_actions

logger = logging.getLogger(__name__)


class PsyintPlugin(ChimeraPlugin):
    """
    Registers the Active PSYINT (psyint) module.
    """

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return "psyint"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer application for this plugin."""
        return psyint_app

    def initialize(self):
        """
        Initializes the plugin by registering its high-risk actions
        with the Action Governance registry.
        """
        logger.info("Initializing PSYINT plugin and registering governance actions.")
        register_psyint_actions()