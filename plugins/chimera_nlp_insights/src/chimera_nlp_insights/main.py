import typer

# Import the plugin interface
from chimera_intel.core.plugin_interface import ChimeraPlugin

# Import the Typer apps you want to combine
from chimera_intel.core.sentiment_time_series import sentiment_time_series_app
from chimera_intel.core.topic_clusterer import topic_clusterer_app

# Create a new parent Typer app for this plugin
nlp_app = typer.Typer(
    name="nlp",
    help="Advanced NLP Insights: Sentiment Time Series and Topic Clustering.",
    no_args_is_help=True,
)

# Add the existing and new apps as subcommands
nlp_app.add_typer(
    sentiment_time_series_app,
    name="sentiment",
    help="Track sentiment over time and flags significant shifts.",
)
nlp_app.add_typer(
    topic_clusterer_app,
    name="cluster",
    help="Analyze documents to find and name emerging topic clusters.",
)


class NLPEnhancementsPlugin(ChimeraPlugin):
    """
    A plugin to bundle advanced NLP functionality.
    It exposes 'sentiment' (from core) and 'cluster' (new)
    under the 'nlp' command.
    """

    @property
    def name(self) -> str:
        return "NLPEnhancements"

    @property
    def app(self) -> typer.Typer:
        """Returns the combined Typer app."""
        return nlp_app

    def initialize(self):
        """Perform any plugin-specific setup."""
        # You could add initialization logic here if needed
        pass