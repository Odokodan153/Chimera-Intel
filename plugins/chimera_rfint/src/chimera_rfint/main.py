from chimera_intel.core.rfint import rfint_app
from chimera_intel.core.plugin_interface import (
    ChimeraPlugin, 
)
import typer

class RFINTPlugin(ChimeraPlugin):
    """
    A plugin for providing active Radio Frequency Intelligence (RFINT)
    capabilities by interfacing with hardware like SDRs and Wi-Fi/BLE radios.
    """

    @property
    def name(self) -> str:
        return "RFINT"

    @property
    def app(self) -> typer.Typer:
        """Returns the Typer app for the RFINT CLI commands."""
        return rfint_app
    
    def initialize(self):
        """Initialize the risk analyzer plugin."""
        pass

# This function is the entry point for the plugin system
def register() -> ChimeraPlugin:
    """Registers the RFINT plugin."""
    return RFINTPlugin()