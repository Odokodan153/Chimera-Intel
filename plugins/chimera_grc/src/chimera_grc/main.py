import typer

from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the new GRC modules
from chimera_intel.core.data_custodian import data_custodian_app
from chimera_intel.core.privacy_impact_reporter import privacy_impact_reporter_app
from chimera_intel.core.source_trust_model import source_trust_model_app
from chimera_intel.core.evidence_vault import vault_app

# Create a new parent Typer app for this plugin
# The 'name' here is for help text, the plugin 'name' property
# below is what sets the actual command.
grc_app = typer.Typer(
    name="grc",
    help="Governance, Risk, and Compliance (GRC) Services.",
    no_args_is_help=True,
)

# Add the subcommands with distinct names
grc_app.add_typer(
    data_custodian_app,
    name="custodian",
    help="Manage auditable integrity, timestamps, and judicial holds."
)
grc_app.add_typer(
    privacy_impact_reporter_app,
    name="privacy-report",
    help="Generate Privacy Impact Reports for datasets."
)
grc_app.add_typer(
    source_trust_model_app,
    name="trust-model",
    help="Get risk-weighted confidence scores for info sources."
)
grc_app.add_typer(
    vault_app,
    name="vault",  # <-- RENAMED from "grc" to "vault"
    help="Manages the secure Encrypted Evidence Vault." # <-- Updated help
)


class GRCPlugin(ChimeraPlugin):
    """
    A plugin to bundle GRC functionality.
    - `custodian`: Auditable integrity and data holds.
    - `privacy-report`: PII scanning and reporting.
    - `trust-model`: Source confidence scoring.
    - `vault`: Encrypted evidence storage and retrieval.
    """

    @property
    def name(self) -> str:
        """This sets the actual command name: 'chimera grc'"""
        return "grc" # <-- CHANGED from "GRCServices" to "grc"

    @property
    def app(self) -> typer.Typer:
        """Returns the combined Typer app."""
        return grc_app

    def initialize(self):
        """No initialization needed for this plugin."""
        pass