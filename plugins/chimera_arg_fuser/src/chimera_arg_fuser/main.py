"""
(NEW) ARG Fuser Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.arg_fuser import arg_fuser_app


class ArgFuserPlugin(ChimeraPlugin):
    """(NEW) ARG Fuser plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name
        # e.g., 'chimera arg-fuser'
        return "arg-fuser"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return arg_fuser_app

    def initialize(self):
        """Initializes the plugin."""
        pass