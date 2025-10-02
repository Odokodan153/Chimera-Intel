"""
Advanced Analysis & AI Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.ai_core import ai_app
from chimera_intel.core.differ import diff_app
from chimera_intel.core.forecaster import forecast_app
from chimera_intel.core.strategist import strategy_app
from chimera_intel.core.pestel_analyzer import pestel_analyzer_app
from chimera_intel.core.competitive_analyzer import competitive_analyzer_app
from chimera_intel.core.lead_suggester import lead_suggester_app
from chimera_intel.core.geo_strategist import geo_strategist_app


class AnalysisPlugin(ChimeraPlugin):
    """Advanced Analysis & AI plugin."""

    @property
    def name(self) -> str:
        # This defines the top-level command name (e.g., 'chimera analysis')

        return "analysis"

    @property
    def app(self) -> typer.Typer:
        # We create a new Typer app here to register all the sub-commands

        analysis_group_app = typer.Typer(help="Run AI-powered and historical analysis.")
        analysis_group_app.add_typer(
            ai_app, name="core", help="Run basic AI analysis (Sentiment, SWOT)."
        )
        analysis_group_app.add_typer(
            diff_app,
            name="diff",
            help="Compare two historical scans to detect changes.",
        )
        analysis_group_app.add_typer(
            forecast_app,
            name="forecast",
            help="Forecasts potential future events from historical data.",
        )
        analysis_group_app.add_typer(
            strategy_app,
            name="strategy",
            help="Generates an AI-powered strategic profile of a target.",
        )
        analysis_group_app.add_typer(
            pestel_analyzer_app,
            name="pestel",
            help="Generates an AI-powered PESTEL analysis.",
        )
        analysis_group_app.add_typer(
            competitive_analyzer_app,
            name="competitive",
            help="Generates an AI-powered comparison of two targets.",
        )
        analysis_group_app.add_typer(
            lead_suggester_app,
            name="suggest-leads",
            help="AI suggests next steps for the active project.",
        )
        analysis_group_app.add_typer(
            geo_strategist_app,
            name="geo-strategy",
            help="Generates a geographic intelligence report.",
        )
        return analysis_group_app

    def initialize(self):
        """Initializes the Advanced Analysis & AI plugin."""
        pass
