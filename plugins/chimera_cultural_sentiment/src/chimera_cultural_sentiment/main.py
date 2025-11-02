"""
HUMINT - Cultural Sentiment Analysis Plugin for Chimera Intel.
"""

import typer
from chimera_intel.core.plugin_interface import ChimeraPlugin
from chimera_intel.core.cultural_sentiment import cultural_sentiment_app


class CulturalSentimentPlugin(ChimeraPlugin):
    """HUMINT plugin that provides cultural sentiment analysis commands."""

    @property
    def name(self) -> str:
        """This will be part of the 'humint' command group."""
        return "humint"

    @property
    def app(self) -> typer.Typer:
        """
        We need a new Typer app to mount the cultural_sentiment_app onto.
        """
        plugin_app = typer.Typer()
        plugin_app.add_typer(
            cultural_sentiment_app,
            name="cultural-sentiment",
            help="Analyze sentiment within a specific cultural context."
        )
        return plugin_app

    def initialize(self):
        """Initializes the Cultural Sentiment plugin."""
        pass