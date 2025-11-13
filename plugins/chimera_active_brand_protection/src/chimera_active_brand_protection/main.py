"""
Plugin definition for Active Brand Protection.
"""
from main_core.plugins import PluginInterface  # Assuming a base plugin interface
import typer
from active_brand_protection import app as active_brand_protection_cli

class ActiveBrandProtectionPlugin(PluginInterface):
    """
    Integrates Active Brand Protection (Defensive Counter-Intel)
    """
    
    @property
    def name(self) -> str:
        """Returns the plugin's name."""
        return "ActiveBrandProtection"
        
    @property
    def app(self) -> typer.Typer:
        """
        Returns the Typer CLI app for this module.
        """
        # This allows the main CLI to add this as a subcommand
        return active_brand_protection_cli
    
    def initialize(self):
        """
        Registers the module's logic or services with the main application.
        """
        # Example: Registering the class for internal use
        # app_context.register_service("abp", ActiveBrandProtection)
        print("ActiveBrandProtection Plugin Registered.")
