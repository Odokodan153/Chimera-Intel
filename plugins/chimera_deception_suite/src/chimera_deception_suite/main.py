"""
Chimera Intel Plugin for the Deception & Disinformation Suite.

This plugin registers the following new command groups:
- disinfo: For synthetic narrative mapping.
- voice-match: For adversary voice comparison.
- reputation: For reputation degradation modeling.
"""

import typer

try:
    from chimera_intel.core.plugin_interface import ChimeraPlugin
    from chimera_intel.core.disinformation_analyzer import disinformation_app
    from chimera_intel.core.adversary_voice_matcher import voice_match_app
    from chimera_intel.core.reputation_model import reputation_app
except ImportError as e:
    print(f"Error loading core modules for chimera_deception_suite: {e}")
    print("Please ensure the core 'chimera_intel' package is installed and accessible.")
    raise

# Define the plugin class, inheriting from ChimeraPlugin
class DeceptionSuitePlugin(ChimeraPlugin):
    """
    Plugin for advanced disinformation, deepfake, and reputation analysis.
    """

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return "deception_suite"

    @property
    def app(self) -> typer.Typer:
        """
        Creates and returns the Typer app for this plugin.
        
        This app groups the individual analysis modules under
        their own sub-commands, following the pattern from
        the automation plugin.
        """
        # Create a new top-level app for this plugin
        plugin_app = typer.Typer()

        # Add each module's app as a named sub-command
        plugin_app.add_typer(
            disinformation_app,
            name="disinfo",
            help="Run synthetic narrative mapping and disinformation analysis."
        )
        plugin_app.add_typer(
            voice_match_app,
            name="voice-match",
            help="Match audio against a library of known adversary voice profiles."
        )
        plugin_app.add_typer(
            reputation_app,
            name="reputation",
            help="Run reputation degradation modeling and impact analysis."
        )

        return plugin_app

    def initialize(self):
        """Initializes the plugin (no-op for this plugin)."""
        pass