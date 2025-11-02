"""
Plugin to add Open-Source Data Intelligence (OS-DATAINT) capabilities.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.open_data_intel import open_data_app

class OpenDataPlugin(ChimeraPlugin):
    """
    A plugin for querying open-source financial and economic datasets.
    """

    @property
    def name(self) -> str:
        """The name of the plugin."""
        return "Open Data Intel"

    @property
    def app(self) -> typer.Typer:
        """The Typer application instance for the plugin's commands."""
        return open_data_app

    def initialize(self):
        """Initialize the plugin (e.g., load resources)."""
        # No specific initialization needed for this plugin
        pass
