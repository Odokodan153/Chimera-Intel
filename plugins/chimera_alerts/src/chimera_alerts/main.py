"""
Plugin for managing and viewing system alerts.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.alert_manager import alert_app

class AlertManagerPlugin(ChimeraPlugin):
    
    @property
    def name(self) -> str:
        return "alerts"

    @property
    def app(self) -> typer.Typer:
        """
        Returns the Typer application for the alert manager.
        """
        return alert_app

    def initialize(self):
        return "Manage and view system alerts."

