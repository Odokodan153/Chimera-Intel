import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the network scanner's Typer app
from chimera_intel.core.network_scanner import network_scan_app


class NetworkScannerPlugin(ChimeraPlugin):
    """
    Plugin for network port scanning and banner grabbing.
    """

    @property
    def name(self) -> str:
        # This is the command name (e.g., `chimera network ...`)
        return "network"

    @property
    def app(self) -> typer.Typer:
        # Return the Typer app instance
        return network_scan_app

    def initialize(self):
        """Initializes the Network Scanner plugin."""
        # No playbooks to register, so we just pass.
        pass