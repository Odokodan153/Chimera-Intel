"""
Plugin entry point for the Persona Profiler module.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
# Import the Typer app from the core module
from chimera_intel.core.persona_profiler import persona_app


class PersonaProfilerPlugin(ChimeraPlugin):
    """
    Registers the 'persona' command with the Chimera CLI.
    """
    
    @property
    def name(self) -> str:
        # Registers as a top-level command: 'chimera persona'
        return "persona"

    @property
    def app(self) -> typer.Typer:
        # Point directly to the app in the core module
        return persona_app

    def initialize(self):
        pass