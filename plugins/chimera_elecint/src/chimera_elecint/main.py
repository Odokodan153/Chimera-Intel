import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.elecint import app as elecint_app


class ElecintPlugin(ChimeraPlugin):
    """
    ELECINT (Electoral/Political Intelligence) plugin.
    Provides tools for tracking campaign finance, analyzing political sentiment,
    and tracing disinformation.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera elecint'."""
        return "elecint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'elecint' command."""
        plugin_app = typer.Typer(
            name="elecint",
            help="Electoral/Political Intelligence (ELECINT) Module.",
            no_args_is_help=True,
        )

        plugin_app.add_typer(elecint_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the ELECINT plugin."""
        pass


# The plugin manager will discover and instantiate this class

plugin = ElecintPlugin()
