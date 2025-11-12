"""
Chimera Intel Plugin: Creative Asset Workflow
Registers the 'creative-workflow' command.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.creative_workflow import creative_app


class CreativeWorkflowPlugin(ChimeraPlugin):
    """Creative Asset Workflow plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera creative-workflow')
        return "creative-workflow"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module
        return creative_app

    def initialize(self):
        """Initializes the Creative Asset Workflow plugin."""
        pass