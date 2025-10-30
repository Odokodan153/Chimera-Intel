import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.spaceint import app as spaceint_app


class SpaceintPlugin(ChimeraPlugin):
    """
    SPACEINT (Space Intelligence) plugin.
    This plugin provides tools for tracking satellites, monitoring launches,
    and predicting satellite flyovers.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera spaceint'."""
        return "spaceint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'spaceint' command."""
        # Create the top-level command for the plugin

        plugin_app = typer.Typer(
            name="spaceint",
            help="Space Intelligence (SPACEINT) Module.",
            no_args_is_help=True,
        )

        # Attach the core SPACEINT commands (track, launches, predict)
        # This will make them available under 'chimera spaceint run <command>'

        plugin_app.add_typer(spaceint_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the SPACEINT plugin."""
        pass


# The plugin manager will discover and instantiate this class

plugin = SpaceintPlugin()
