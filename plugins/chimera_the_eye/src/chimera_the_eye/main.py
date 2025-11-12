"""
Chimera-Intel Plugin: The Eye Orchestrator (Phase 3)

This plugin provides a CLI entry point to run "The Eye"
as a plugin, respecting multi-tenancy.
"""

import asyncio
import click
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.the_eye import TheEye

class TheEyePlugin(ChimeraPlugin):
    """
    A plugin wrapper for The Eye orchestrator.
    This allows it to be called from the main Chimera CLI.
    """
    
    def __init__(self):
        self.name = "TheEye"
        self.description = "Central AI intelligence, orchestrator, and data analyzer."
        self.version = "1.0.0"
        self.core_instance: TheEye = None

    def load(self, *args, **kwargs) -> bool:
        """
        Loads the plugin. The core instance is loaded on-demand in `run`.
        """
        return True

    def run(self, **kwargs) -> bool:
        """
        Parses CLI arguments and starts the main discovery run for The Eye.
        
        Expected kwargs:
            identifier (str): The search target.
            tenant_id (str): The tenant ID for this investigation.
        """
        identifier = kwargs.get("identifier")
        tenant_id = kwargs.get("tenant_id")

        if not identifier:
            print("Error: 'identifier' argument is required.")
            return False
        
        if not tenant_id:
            print("Error: 'tenant_id' argument is required for this enterprise plugin.")
            return False

        try:
            print(f"Loading The Eye for Tenant: {tenant_id}")
            # Initialize The Eye with the specific tenant ID
            self.core_instance = TheEye(tenant_id=tenant_id)
            
            print(f"Running The Eye discovery for: {identifier}")
            asyncio.run(self.core_instance.run(identifier))
            return True
        except Exception as e:
            print(f"An error occurred during The Eye run: {e}")
            return False

    def get_cli_command(self) -> click.Command:
        """
        Returns the Click command for this plugin.
        """
        @click.command(name="the_eye", help=self.description)
        @click.option("--identifier", required=True, help="The target to investigate (e.g., 'acme.com')")
        @click.option("--tenant", required=True, help="The tenant ID for this investigation.")
        def cli(identifier, tenant):
            """
            Run the 🧿 The Eye investigation.
            """
            self.run(identifier=identifier, tenant_id=tenant)
        
        return cli

    def unload(self) -> bool:
        self.core_instance = None
        return True

    async def discover(self, identifier: str):
        """Not applicable. The Eye is an orchestrator."""
        pass

def register() -> ChimeraPlugin:
    """
    Entry point for the Chimera-Intel plugin manager.
    """
    return TheEyePlugin()