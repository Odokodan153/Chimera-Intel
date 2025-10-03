import pytest
from unittest.mock import patch, MagicMock
from chimera_intel.core.narrative_analyzer import (
    track_narrative,
    narrative_analyzer_app,
)
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture
def mock_gnews():
    with patch("chimera_intel.core.narrative_analyzer.fetch_news") as mock:
        mock.return_value = [
            {"source": {"name": "Mock News"}, "title": "A Test Article"}
        ]
        yield mock


@pytest.fixture
def mock_tweepy():
    with patch("chimera_intel.core.narrative_analyzer.tweepy.Client") as mock:
        mock_tweet = MagicMock()
        mock_tweet.author_id = "mock_user"
        mock_tweet.text = "A test tweet about a topic."

        mock_client_instance = mock.return_value
        mock_client_instance.search_recent_tweets.return_value.data = [mock_tweet]
        yield mock


@pytest.fixture
def mock_ai_sentiment():
    with patch(
        "chimera_intel.core.narrative_analyzer.perform_sentiment_analysis"
    ) as mock:
        # Let's have it return different sentiments to make the test more robust

        mock.side_effect = ["Positive", "Negative"]
        yield mock


def test_track_narrative_returns_analyzed_data(
    mock_gnews, mock_tweepy, mock_ai_sentiment
):
    """
    Tests that the track_narrative function returns a list of dictionaries
    with the sentiment analysis results included.
    """
    # The function is called within the typer command, so we can call it directly
    # for a unit test.

    result = track_narrative(query="test query")

    assert isinstance(result, list)
    assert len(result) == 2
    # Check that the sentiment from our mock is now in the returned data

    assert "sentiment" in result[0]
    assert result[0]["sentiment"] == "Positive"
    assert result[1]["sentiment"] == "Negative"


def test_track_narrative_cli_command(mock_gnews, mock_tweepy, mock_ai_sentiment):
    """
    Tests that the CLI command still runs correctly and prints the output table.
    """
    result = runner.invoke(narrative_analyzer_app, ["track", "--track", "test query"])

    assert result.exit_code == 0
    assert "Narrative Analysis Summary" in result.stdout
    assert "A Test Article" in result.stdout
    assert "A test tweet" in result.stdout
    # Check for sentiment in the output

    assert "Positive" in result.stdout
    assert "Negative" in result.stdout
