import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.prodint import app as prodint_app


class ProdintPlugin(ChimeraPlugin):
    """
    PRODINT (Product Intelligence) plugin.
    Provides tools for competitive product analysis using live data for
    digital teardowns and churn analysis.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera prodint'."""
        return "prodint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'prodint' command."""
        plugin_app = typer.Typer(
            name="prodint",
            help="Product Intelligence (PRODINT) Module.",
            no_args_is_help=True,
        )

        plugin_app.add_typer(prodint_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the PRODINT plugin."""
        pass


# The plugin manager will discover and instantiate this class

plugin = ProdintPlugin()
