import pytest
from unittest.mock import MagicMock

# The class to be tested

from chimera_intel.core.cognitive_warfare_engine import CognitiveWarfareEngine
from chimera_intel.core.schemas import SentimentAnalysisResult


@pytest.fixture
def mock_api_keys(mocker):
    """A pytest fixture to mock the API keys required by underlying modules."""
    mocker.patch(
        "chimera_intel.core.narrative_analyzer.API_KEYS.gnews_api_key", "fake_gnews_key"
    )
    mocker.patch(
        "chimera_intel.core.narrative_analyzer.API_KEYS.twitter_bearer_token",
        "fake_twitter_token",
    )
    mocker.patch(
        "chimera_intel.core.narrative_analyzer.API_KEYS.google_api_key",
        "fake_google_key",
    )


@pytest.fixture
def mock_external_fetches(mocker):
    """A pytest fixture to mock the functions that fetch data from external news and social media APIs."""
    # Mock the news fetching function

    mocker.patch(
        "chimera_intel.core.narrative_analyzer.fetch_news",
        return_value=[{"source": {"name": "Test News"}, "title": "A positive story"}],
    )
    # Mock the tweet fetching function

    mock_tweet = MagicMock()
    mock_tweet.author_id = "123"
    mock_tweet.text = "A negative tweet"
    mocker.patch(
        "chimera_intel.core.narrative_analyzer.fetch_tweets",
        return_value=[mock_tweet],
    )
    # Mock the sentiment analysis function

    def mock_sentiment_side_effect(text):
        if "positive" in text.lower():
            return SentimentAnalysisResult(label="Positive", score=0.9)
        return SentimentAnalysisResult(label="Negative", score=0.8)

    mocker.patch(
        "chimera_intel.core.narrative_analyzer.analyze_sentiment",
        side_effect=mock_sentiment_side_effect,
    )


def test_trigger_identification(mock_api_keys, mock_external_fetches):
    """
    Tests the logic for identifying psychological triggers in text after loading narratives.
    """
    # --- Act ---
    # Initialize the engine, which will use the mocked data

    engine = CognitiveWarfareEngine(narrative_query="test", twitter_keywords=None)

    # --- Assert ---
    # The primary goal is to ensure initialization succeeds without errors.
    # We can also check that the narratives were loaded as expected.

    assert len(engine.narratives) == 2
    assert engine.narratives[0]["sentiment"] == "Positive"
    assert engine.narratives[1]["sentiment"] == "Negative"

    # Now, test the actual trigger identification method

    text_with_trigger = "This event will create a scarcity of resources."
    triggers = engine.identify_triggers(text_with_trigger)

    assert "Scarcity" in triggers
    assert triggers["Scarcity"] > 0.8  # Check for a high confidence score
