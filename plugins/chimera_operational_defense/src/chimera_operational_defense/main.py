import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the Typer apps from the core modules
from chimera_intel.core.red_team import red_team_app
from chimera_intel.core.counter_intelligence import counter_intel_app
from chimera_intel.core.deception_detector import deception_app
from chimera_intel.core.supply_chain_risk import supply_chain_app

# Define the main plugin app
ops_app = typer.Typer(
    name="ops",
    help="Operational Defense & Red Team Suite",
    no_args_is_help=True,
)

# Add the imported apps as subcommands
ops_app.add_typer(
    red_team_app, 
    name="red-team", 
    help="Adversary Emulation & Red Team Analysis"
)
ops_app.add_typer(
    counter_intel_app,
    name="counter-intel",
    help="Counterintelligence & Insider Threat Scoring"
)
ops_app.add_typer(
    deception_app,
    name="deception",
    help="Corporate Deception & Mimicry Detection"
)
ops_app.add_typer(
    supply_chain_app,
    name="supply-chain",
    help="Supply Chain Risk Monitoring"
)


class OperationalDefensePlugin(ChimeraPlugin):
    """
    A plugin that groups all operational security modules under one command.
    
    This provides:
    - `ops red-team ...` (Adversary Emulation)
    - `ops counter-intel ...` (Counterintelligence)
    - `ops deception ...` (Deception Detection)
    - `ops supply-chain ...` (Supply Chain Monitoring)
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "OperationalDefense"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return ops_app

    def initialize(self):
        """A method to perform any setup for the plugin."""
        # No specific initialization needed for this plugin
        pass