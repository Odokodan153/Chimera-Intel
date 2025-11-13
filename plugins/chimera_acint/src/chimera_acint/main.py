"""
Acoustic Intelligence (ACINT) Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.acint import acint_app

class ACINTPlugin(ChimeraPlugin):
    """
    Plugin for Acoustic Intelligence (ACINT).
    
    Orchestrates modules for:
    - Ingesting and building signature libraries (e.g., machinery, engines).
    - Monitoring soundscapes for anomalies (e.g., gunfire, explosions).
    - Cross-referencing acoustic signatures with other INTs.
    """

    @property
    def name(self) -> str:
        """This defines the top-level command name: 'chimera acint'"""
        return "acint"

    @property
    def app(self) -> typer.Typer:
        """This points to the Typer app instance in the core module."""
        return acint_app

    def initialize(self):
        """Initializes the ACINT plugin."""
        # No initialization needed for this plugin
        pass