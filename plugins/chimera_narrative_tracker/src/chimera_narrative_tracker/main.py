"""
Plugin to register the Narrative Tracker (NARINT) module.
"""
import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.narrative_tracker import app as narrative_app
class NarrativePlugin(ChimeraPlugin):

    @property
    def name(self) -> str:
        # This defines the command name
        return "Narrative Tracker"

    @property
    def app(self) -> typer.Typer:
        # This points to the existing Typer app instance in the core module
        return narrative_app

    def initialize(self):
        """Initializes the Narrative Tracker plugin."""
        # No special initialization is needed for this plugin
        pass