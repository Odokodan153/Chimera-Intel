# plugins/chimera_adversary_simulator/src/chimera_adversary_simulator/main.py

import typer
from src.chimera_intel.core.plugin_interface import ChimeraPlugin
from src.chimera_intel.core.adversary_simulator import app as adversary_sim_app
from src.chimera_intel.core.utils import console

class AdversarySimulatorPlugin(ChimeraPlugin):
    """
    Plugin for the Adversary Simulation (CALDERA) Engine.
    Provides CLI commands to interact with CALDERA.
    """

    @property
    def name(self) -> str:
        """This defines the command name: 'chimera adversary-sim'."""
        return "adversary-sim"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer app for the 'adversary-sim' command group."""
        return adversary_sim_app

    def initialize(self):
        """
        Initializes the Adversary Simulator plugin.
        """
        console.print(
            "[AdversarySim Plugin] [bold green]Active[/bold green]. CALDERA integration enabled."
        )


# The plugin manager will discover and instantiate this class
plugin = AdversarySimulatorPlugin()