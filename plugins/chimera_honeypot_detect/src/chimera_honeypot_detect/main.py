"""
Plugin entry point for the Honeypot Detector module.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
# Import the Typer app from the core module
from chimera_intel.core.honeypot_detector import honeypot_app


class HoneypotDetectPlugin(ChimeraPlugin):
    """
    Registers the 'honeypot' command with the Chimera CLI.
    """
    
    @property
    def name(self) -> str:
        # Registers as a top-level command: 'chimera honeypot'
        return "honeypot"

    @property
    def app(self) -> typer.Typer:
        # Point directly to the app in the core module
        return honeypot_app

    def initialize(self):
        pass