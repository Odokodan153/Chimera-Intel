"""
Plugin definition for MEDINT (Medical Intelligence).
"""
from main_core.plugins import PluginInterface  # Assuming a base plugin inter
import typer
from medint import app as medint_cli

class MedintPlugin(PluginInterface):
    """
    Integrates the MEDINT module.
    """
    
    @property
    def name(self) -> str:
        """Returns the plugin's name."""
        return "MEDINT"

    @property
    def app(self) -> typer.Typer:
        """
        Returns the Typer CLI app for this module.
        """
        # This allows the main CLI to add this as a subcommand
        return medint_cli

    def initialize(self):
        """
        Registers the module's logic or services with the main application.
        """
        # Example: Registering the class for internal use
        # from medint import MedicalIntelligence
        # app_context.register_service("medint", MedicalIntelligence)
        print("MEDINT Plugin Registered.")