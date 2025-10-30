# plugins/chimera_masint/src/chimera_masint/main.py
import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.masint import app as masint_app


class MasintPlugin(ChimeraPlugin):
    """
    MASINT (Measurement and Signature Intelligence) plugin.
    This plugin provides tools for analyzing unique signatures from various sources,
    such as RF, acoustic, and thermal data.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera masint'."""
        return "masint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'masint' command."""
        # Create the top-level command for the plugin
        plugin_app = typer.Typer(
            name="masint",
            help="Measurement and Signature Intelligence (MASINT) Module.",
            no_args_is_help=True,
        )

        # Attach the core MASINT commands (rf-pcap, acoustic, thermal)
        # This will make them available under 'chimera masint run <command>'
        plugin_app.add_typer(masint_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the MASINT plugin. No specific initialization needed for now."""
        pass


# The plugin manager will discover and instantiate this class
plugin = MasintPlugin()
