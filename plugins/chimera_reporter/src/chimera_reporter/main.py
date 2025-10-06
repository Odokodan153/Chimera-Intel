"""
Reporter Plugin for Chimera Intel.

This plugin provides functionalities to generate various types of reports,
such as PDFs and interactive graphs, from the collected intelligence data.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.reporter import report_app


class ReporterPlugin(ChimeraPlugin):
    """Reporting plugin for Chimera Intel."""

    @property
    def name(self) -> str:
        """
        Returns the name of the plugin.
        This will be used as the command name in the CLI (e.g., 'chimera reporter').
        """
        return "reporter"

    @property
    def app(self) -> typer.Typer:
        """
        Returns the Typer application for the plugin.
        This points to the 'report_app' instance from the core reporter module.
        """
        return report_app

    def initialize(self):
        """
        Initializes the Reporter plugin.
        This method can be used for any setup required by the plugin.
        """
        pass