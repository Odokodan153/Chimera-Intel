import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.fusion import (
    app as fusion_app,
)  # Import the app from the core module


class DataFusionPlugin(ChimeraPlugin):
    """
    Multi-Modal Data Fusion (4D Analysis) Plugin.
    Provides tools to fuse disparate data points into a single
    Master Entity Profile and generate predictive insights.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera fusion'."""
        return "fusion"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'fusion' command."""
        plugin_app = typer.Typer(
            name="fusion",
            help="Multi-Modal Data Fusion (4D Analysis) Engine.",
            no_args_is_help=True,
        )

        # Add the 'run' command from the core fusion.py
        plugin_app.add_typer(fusion_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the Data Fusion plugin."""
        pass


# The plugin manager will discover and instantiate this class
plugin = DataFusionPlugin()