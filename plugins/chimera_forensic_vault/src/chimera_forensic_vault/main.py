"""
Chimera Intel Plugin: Forensic Vault & Attribution
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.forensic_vault import vault_app


class ForensicVaultPlugin(ChimeraPlugin):
    """
    Registers the Forensic Vault (hash, reverse-search, sign, timestamp)
    commands with the main Chimera CLI.
    """

    @property
    def name(self) -> str:
        """The name of the plugin, used for registration."""
        return "forensic_vault"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return vault_app

    def initialize(self):
        """A method to perform any setup for the plugin."""
        # No specific initialization needed for this plugin
        pass