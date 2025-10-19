import pytest
from unittest.mock import patch, MagicMock
from chimera_intel.core.narrative_analyzer import (
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
    """
    Corrected mock to patch 'fetch_tweets' directly, bypassing the API key
    check inside it.
    """
    with patch("chimera_intel.core.narrative_analyzer.fetch_tweets") as mock:
        mock_tweet = MagicMock()
        mock_tweet.author_id = "mock_user"
        mock_tweet.text = "A test tweet about a topic."
        # fetch_tweets returns a list of tweet objects

        mock.return_value = [mock_tweet]
        yield mock


@pytest.fixture
def mock_ai_sentiment():
    with patch("chimera_intel.core.narrative_analyzer.analyze_sentiment") as mock:
        mock.return_value.label = "Positive"
        yield mock


# Removed the broken 'test_track_narrative_returns_analyzed_data' test.
# It was calling a typer command function directly, which is incorrect.
# The CLI test below correctly tests the functionality.


def test_track_narrative_cli_command(mock_gnews, mock_tweepy, mock_ai_sentiment):
    """
    Tests that the CLI command runs correctly and prints the output table.
    """
    result = runner.invoke(narrative_analyzer_app, ["track", "--track", "test query"])

    assert result.exit_code == 0
    assert "Narrative Analysis Summary" in result.stdout
    assert "A Test Article" in result.stdout
    assert "A test tweet" in result.stdout
    # Check for sentiment in the output

    assert "Positive" in result.stdout
