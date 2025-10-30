import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.qint import app as qint_app


class QintPlugin(ChimeraPlugin):
    """
    QINT (Quantum Intelligence) plugin.
    Provides tools to monitor quantum technology research, readiness levels,
    and post-quantum cryptography developments.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera qint'."""
        return "qint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'qint' command."""
        plugin_app = typer.Typer(
            name="qint",
            help="Quantum Intelligence (QINT) Module.",
            no_args_is_help=True,
        )

        plugin_app.add_typer(qint_app, name="run")

        return plugin_app

    def initialize(self):
        """Initializes the QINT plugin."""
        pass


# The plugin manager will discover and instantiate this class

plugin = QintPlugin()
