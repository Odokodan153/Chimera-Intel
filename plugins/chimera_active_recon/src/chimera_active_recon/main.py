"""
Active Reconnaissance Plugin for Chimera Intel.

This plugin:
1. Exposes the 'active-recon' CLI command group (from core.active_recon).
2. Registers the active recon playbooks with the AutomationManager on initialization.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.active_recon import active_recon_app, register_active_recon_playbooks
from chimera_intel.core.logger_config import setup_logging

logger = setup_logging()

class ActiveReconPlugin(ChimeraPlugin):
    """
    Exposes CLI commands and registers automated playbooks for Active Recon.
    """

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera active-recon')
        return "active-recon"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        # Provides the 'chimera active-recon run' command
        return active_recon_app

    def initialize(self):  # <<< FIX: Changed to initialize(self)
        """
        Initializes the plugin by registering its playbooks.
        """
        logger.info("Initializing ActiveRecon Plugin...")
        try:
            register_active_recon_playbooks()
        except Exception as e:
            logger.error(f"Failed to initialize ActiveRecon Plugin: {e}", exc_info=True)