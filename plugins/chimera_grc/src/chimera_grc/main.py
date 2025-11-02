import typer

from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the new GRC modules
from chimera_intel.core.data_custodian import data_custodian_app
from chimera_intel.core.privacy_impact_reporter import privacy_impact_reporter_app
from chimera_intel.core.source_trust_model import source_trust_model_app

# Create a new parent Typer app for this plugin
grc_app = typer.Typer(
    name="grc",
    help="Governance, Risk, and Compliance (GRC) Services.",
    no_args_is_help=True,
)

# Add the new apps as subcommands
grc_app.add_typer(
    data_custodian_app,
    name="custodian",
    help="Manage auditable integrity, timestamps, and judicial holds.",
)
grc_app.add_typer(
    privacy_impact_reporter_app,
    name="privacy-report",
    help="Generate Privacy Impact Reports for datasets.",
)
grc_app.add_typer(
    source_trust_model_app,
    name="trust-model",
    help="Get risk-weighted confidence scores for info sources.",
)


class GRCPlugin(ChimeraPlugin):
    """
    A plugin to bundle GRC functionality.
    - `custodian`: Auditable integrity and data holds.
    - `privacy-report`: PII scanning and reporting.
    - `trust-model`: Source confidence scoring.
    """

    @property
    def name(self) -> str:
        return "GRCServices"

    @property
    def app(self) -> typer.Typer:
        """Returns the combined Typer app."""
        return grc_app

    def initialize(self):
        """No initialization needed for this plugin."""
        pass