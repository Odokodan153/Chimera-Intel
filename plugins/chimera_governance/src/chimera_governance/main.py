"""
Chimera Intel Plugin for Media Governance.

This plugin registers the 'gov' command group, which provides
tools for managing media approval workflows and consent logs.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.media_governance import governance_app


class MediaGovernancePlugin(ChimeraPlugin):
    """
    Registers the media_governance module's Typer app.
    """

    @property
    def name(self) -> str:
        """Returns the plugin's name."""
        # This name should match the 'name' in the core 'governance_app'
        return "gov"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer app to be registered."""
        return governance_app

    def initialize(self):
        """A required method, but no initialization needed here."""
        pass