"""
Purple Team Plugin for Chimera-Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
# Import the Typer app from the new core CLI file
from chimera_intel.core.purple_team_cli import purple_team_app


class PurpleTeamPlugin(ChimeraPlugin):
    """
    Plugin that registers the purple team commands with the main CLI.
    """

    @property
    def name(self) -> str:
        """Returns the plugin's name."""
        return "purple-team"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer app with this plugin's commands."""
        return purple_team_app

    def initialize(self):
        """Initializes the Purple Team plugin."""
        # No special initialization needed for this plugin
        pass