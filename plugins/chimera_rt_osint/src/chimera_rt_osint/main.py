# plugins/chimera_rt_osint/src/chimera_rt_osint/main.py

import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.rt_osint import rt_osint_app


class RtOsintPlugin(ChimeraPlugin):
    """
    Real-Time OSINT (RT-OSINT) plugin.

    This plugin provides a live monitor for clearnet and
    .onion archive sources, routed via Tor.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera rt-osint'."""
        return "rt-osint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'rt-osint' command."""
        # Create the top-level command for the plugin
        plugin_app = typer.Typer(
            name="rt-osint",
            help="Real-Time OSINT Monitoring Module.",
            no_args_is_help=True,
        )

        # Attach the core RT-OSINT commands
        # This will make them available under 'chimera rt-osint run <command>'
        plugin_app.add_typer(rt_osint_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the RT-OSINT plugin."""
        pass


# The plugin manager will discover and instantiate this class
plugin = RtOsintPlugin()