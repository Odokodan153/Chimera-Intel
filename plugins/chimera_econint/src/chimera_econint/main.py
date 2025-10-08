import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.econint import econint_app


class EconintPlugin(ChimeraPlugin):
    """
    ECONINT (Economic Intelligence) plugin.
    This plugin provides tools to analyze macroeconomic factors and supply chain vulnerabilities.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera econint'."""
        return "econint"

    @property
    def app(self) -> typer.Typer:
        """Creates the Typer app for the 'econint' command."""

        return econint_app

    def initialize(self):
        """Initializes the ECONINT plugin."""
        pass


# The plugin manager will discover and instantiate this class
plugin = EconintPlugin()