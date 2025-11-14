"""
Key Personnel & Org Chart Tracking Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.key_personnel_tracker import key_personnel_app


class KeyPersonnelPlugin(ChimeraPlugin):
    """
    Plugin for Key Personnel & Org Chart Tracking.
    
    Monitors a defined list of high-value individuals (C-suite, VPs,
    lead engineers) to identify strategic movements, "brain drain," and
    "acqui-hire" signals.
    """

    @property
    def name(self) -> str:
        """This defines the top-level command name: 'chimera key-personnel'"""
        return "key-personnel"

    @property
    def app(self) -> typer.Typer:
        """This points to the Typer app instance in the core module."""
        return key_personnel_app

    def initialize(self):
        """Initializes the Key Personnel plugin."""
        # No initialization needed for this plugin
        pass