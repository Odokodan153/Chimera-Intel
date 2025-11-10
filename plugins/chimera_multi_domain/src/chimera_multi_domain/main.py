"""
Multi-Domain (SIGINT, HUMINT, FININT) Correlation Plugin for Chimera Intel.
"""

import typer

# These are imported from the main, installed chimera-intel package
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.multi_domain import multi_domain_app


class MultiDomainPlugin(ChimeraPlugin):
    """Multi-Domain plugin that provides correlation commands."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera multi-domain')
        return "multi-domain"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module
        return multi_domain_app

    def initialize(self):
        """Initializes the Multi-Domain plugin."""
        # No special initialization is needed for this plugin
        pass