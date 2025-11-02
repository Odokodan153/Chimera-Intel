import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the new ARG Typer app
from chimera_intel.core.arg_cli import arg_app


class AdversaryResearchGridPlugin(ChimeraPlugin):
    """
    Global Correlation Graph (ARG) Plugin.
    Provides tools for ingesting data into the global Neo4j graph
    and running complex, cross-domain queries.
    """

    @property
    def name(self) -> str:
        # This is the command name (e.g., `chimera arg ...`)
        return "arg"

    @property
    def app(self) -> typer.Typer:
        # Return the Typer app instance
        return arg_app

    def initialize(self):
        """Initializes the ARG plugin."""
        # This could be used to check GDS library or run migrations
        pass