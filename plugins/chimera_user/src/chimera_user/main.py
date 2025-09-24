"""
User Management Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.user_manager import user_app


class UserPlugin(ChimeraPlugin):
    """User management plugin for handling users and authentication."""

    @property
    def name(self) -> str:
        return "user"

    @property
    def app(self) -> typer.Typer:
        return user_app

    def initialize(self):
        """Initializes the User Management plugin."""
        pass
