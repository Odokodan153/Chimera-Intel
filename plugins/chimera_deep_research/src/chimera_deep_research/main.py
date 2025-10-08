"""
The main plugin entry point for the Strategic Deep Research module.
This file's sole responsibility is to register the deep research commands
with the Chimera Intel framework.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.deep_research import deep_research_app 

class DeepResearchPlugin(ChimeraPlugin):
    """The ultimate strategic intelligence fusion plugin."""

    @property
    def name(self) -> str:
        # This name defines the command group, e.g., 'chimera deep-research'
        return "deep-research"

    @property
    def app(self) -> typer.Typer:
        # The plugin exposes the dedicated CLI app from the core module
        return deep_research_app

    def initialize(self):
        """Initializes the plugin."""
        pass