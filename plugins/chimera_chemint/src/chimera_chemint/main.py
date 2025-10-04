# plugins/chimera_chemint/src/chimera_chemint/main.py

import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.chemint import app as chemint_app


class ChemintPlugin(ChimeraPlugin):
    """
    CHEMINT (Chemical Intelligence) plugin.
    This plugin provides tools for analyzing chemical data, including searching
    for substance information by name or CAS number.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera chemint'."""
        return "chemint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'chemint' command."""
        # Create the top-level command for the plugin

        plugin_app = typer.Typer(
            name="chemint",
            help="Chemical Intelligence (CHEMINT) Module.",
            no_args_is_help=True,
        )

        # Attach the core CHEMINT commands
        # This will make them available under 'chimera chemint run <command>'

        plugin_app.add_typer(chemint_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the CHEMINT plugin."""
        pass


# The plugin manager will discover and instantiate this class

plugin = ChemintPlugin()
