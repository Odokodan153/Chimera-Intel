"""
Analysis Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.social_analyzer import social_analyzer_app
from chimera_intel.core.behavioral_analyzer import behavioral_analyzer_app
from chimera_intel.core.competitive_analyzer import competitive_analyzer_app
from chimera_intel.core.deception_detector import deception_detector_app
from chimera_intel.core.opsec_analyzer import opsec_analyzer_app
from chimera_intel.core.pestel_analyzer import pestel_analyzer_app
from chimera_intel.core.signal_analyzer import signal_analyzer_app
from chimera_intel.core.temporal_analyzer import temporal_analyzer_app
from chimera_intel.core.weak_signal_analyzer import weak_signal_analyzer_app
from chimera_intel.core.io_tracking import io_tracking_app
from chimera_intel.core.narrative_analyzer import narrative_analyzer_app
from chimera_intel.core.attack_path_simulator import attack_path_simulator_app
from chimera_intel.core.cultint import cultint_app
from chimera_intel.core.strategic_forecaster import forecaster_app
from chimera_intel.core.attribution import attribution_app
from chimera_intel.core.cognitive_mapping_analyzer import cognitive_mapping_app
from chimera_intel.core.complexity_analyzer import complexity_analyzer_app
from chimera_intel.core.alternative_hypothesis_generator import alternative_hypothesis_app
from chimera_intel.core.multimodal_reasoning import multimodal_reasoning_app
from chimera_intel.core.event_modeling import event_modeling_app
from chimera_intel.core.sentiment_time_series import sentiment_time_series_app
from chimera_intel.core.bias_audit import bias_audit_app
class AnalysisPlugin(ChimeraPlugin):
    """Analysis plugin."""

    @property
    def name(self) -> str:
        # This defines the command name (e.g., 'chimera analysis')

        return "analysis"

    @property
    def app(self) -> typer.Typer:
        # Create a new Typer app for the 'analysis' command

        analysis_app = typer.Typer(
            name="analysis",
            help="Advanced data analysis and intelligence generation.",
        )
        # Add subcommands from different modules

        analysis_app.add_typer(social_analyzer_app, name="social")
        analysis_app.add_typer(behavioral_analyzer_app, name="behavioral")
        analysis_app.add_typer(competitive_analyzer_app, name="competitive")
        analysis_app.add_typer(deception_detector_app, name="deception")
        analysis_app.add_typer(opsec_analyzer_app, name="opsec")
        analysis_app.add_typer(pestel_analyzer_app, name="pestel")
        analysis_app.add_typer(signal_analyzer_app, name="signal")
        analysis_app.add_typer(temporal_analyzer_app, name="temporal")
        analysis_app.add_typer(weak_signal_analyzer_app, name="wsa")
        analysis_app.add_typer(io_tracking_app, name="influence")
        analysis_app.add_typer(narrative_analyzer_app, name="narrative")
        analysis_app.add_typer(attack_path_simulator_app, name="simulate")
        analysis_app.add_typer(cultint_app, name="cultint")
        analysis_app.add_typer(forecaster_app, name="forecast")
        analysis_app.add_typer(
            attribution_app,
            name="attribution",
            help="Run threat actor attribution and scoring."
        )
        analysis_app.add_typer(
            cognitive_mapping_app,
            name="cognitive-mapping",
            help="Builds cognitive models of key individuals."
        )
        analysis_app.add_typer(
            complexity_analyzer_app,
            name="complexity-analysis",
            help="Maps system interdependencies and predicts cascading failures."
        )
        analysis_app.add_typer(
            alternative_hypothesis_app,
            name="alternative-hypothesis",
            help="Generates competing hypotheses to mitigate confirmation bias."
        )
        analysis_app.add_typer(
            multimodal_reasoning_app,
            name="multimodal-reasoning",
            help="Reasons across different data types (text, image, geo, etc.)."
        )
        analysis_app.add_typer(
            event_modeling_app,
            name="event-modeling",
            help="Reconstructs a verifiable sequence of events from raw data."
        )
        analysis_app.add_typer(
            sentiment_time_series_app,
            name="sentiment-time-series",
            help="Tracks sentiment over time and flags significant shifts."
        )
        analysis_app.add_typer(
            bias_audit_app,
            name="bias-audit",
            help="Meta-analysis to detect bias or gaps in reports."
        )
        
        return analysis_app

    def initialize(self):
        """Initializes the Analysis plugin."""
        pass
