# plugins/chimera_remediation_advisor/src/chimera_remediation_advisor/main.py

"""
Remediation Advisor Plugin for Chimera Intel.

Provides CLI commands to generate "how-to-patch" plans for
vulnerabilities (CVEs), counter-intelligence findings, and 
AI-driven fallback.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.remediation_advisor import remediation_app


class RemediationAdvisorPlugin(ChimeraPlugin):
    """Remediation Advisor plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera remediate')
        return "remediate"

    @property
    def app(self) -> typer.Typer:
        # This points to the Typer app instance in the core module
        return remediation_app

    def initialize(self):
        """Initializes the Remediation Advisor plugin."""
        # No specific initialization needed for this plugin
        pass

# This is the entry point that Chimera Intel's plugin manager will load
plugin = RemediationAdvisorPlugin()