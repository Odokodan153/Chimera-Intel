import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.ecoint import app as ecoint_app


class EcointPlugin(ChimeraPlugin):
    """
    ECOINT (Ecological & Sustainability Intelligence) plugin.
    This plugin provides tools to assess environmental risks, monitor ESG factors,
    and detect potential greenwashing using live data from public APIs.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera ecoint'."""
        return "ecoint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'ecoint' command."""
        plugin_app = typer.Typer(
            name="ecoint",
            help="Ecological & Sustainability Intelligence (ECOINT) Module.",
            no_args_is_help=True,
        )

        # Attach the core ECOINT commands (epa-violations, ghg-emissions)

        plugin_app.add_typer(ecoint_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the ECOINT plugin."""
        pass


# The plugin manager will discover and instantiate this class

plugin = EcointPlugin()
