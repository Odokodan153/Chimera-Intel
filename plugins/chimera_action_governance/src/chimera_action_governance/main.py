"""
Chimera Intel Plugin: Action Governance & Compliance
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.action_governance import gov_app


class ActionGovernancePlugin(ChimeraPlugin):
    """
    Registers the Action Governance module, providing pre-flight checks
    and risk scoring for all system actions.
    """

    @property
    def name(self) -> str:
        """The command name for this plugin."""
        return "governance"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance."""
        return gov_app

    def initialize(self):
        """Initializes the plugin."""
        pass