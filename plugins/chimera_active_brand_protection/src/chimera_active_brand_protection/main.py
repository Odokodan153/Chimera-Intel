"""
Plugin definition for Financial Market Signals.
"""
import typer
from chimera_intel.core.plugin_interface import PluginInterface
from .analysis import app as financial_signals_cli_app

class FinancialMarketSignalsPlugin(PluginInterface):
    """
    Integrates Financial Market Signal Analysis tools.
    """
    
    @property
    def name(self) -> str:
        """Returns the plugin's name."""
        return "FinancialMarketSignals"
        
    @property
    def app(self) -> typer.Typer:
        """
        Returns the Typer CLI app for this module.
        """
        # This allows the main CLI to add this as a subcommand
        return financial_signals_cli_app
    
    def initialize(self):
        """
        Registers the module's logic or services with the main application.
        """
        # Example: Registering the analyzer class for internal use
        # from .analysis import FinancialMarketSignalAnalyzer
        # app_context.register_service("financial_analyzer", FinancialMarketSignalAnalyzer)
        print("FinancialMarketSignals Plugin Registered.")