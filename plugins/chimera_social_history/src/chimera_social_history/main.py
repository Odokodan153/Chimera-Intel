"""
Social Media History Monitoring Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.social_history_monitor import social_history_app


class SocialHistoryMonitorPlugin(ChimeraPlugin):
    """Social media history monitoring plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera social-history')
        return "social-history"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return social_history_app

    def initialize(self):
        """Initializes the Social History Monitoring plugin."""
        pass