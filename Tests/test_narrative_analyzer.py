import pytest
from unittest.mock import patch, MagicMock
from chimera_intel.core.narrative_analyzer import (
    narrative_analyzer_app,
)
from typer.testing import CliRunner
from chimera_intel.core.config_loader import API_KEYS  # Import for patching

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
        # Mock the return object to have a .label attribute
        sentiment_result = MagicMock()
        sentiment_result.label = "Positive"
        mock.return_value = sentiment_result
        yield mock


@pytest.fixture(autouse=True)
def mock_api_keys(monkeypatch):
    """
    FIX: Mocks API keys at the config level to prevent SystemExit(2)
    during module import.
    """
    monkeypatch.setattr(API_KEYS, "gnews_api_key", "fake_key")
    monkeypatch.setattr(API_KEYS, "twitter_bearer_token", "fake_token")


@pytest.fixture(autouse=True)
def mock_sync_client(monkeypatch):
    """
    FIX: Mocks the global sync_client context manager used in fetch_news.
    """
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None
    # Patch the client where it is used
    monkeypatch.setattr(
        "chimera_intel.core.narrative_analyzer.sync_client", mock_client
    )


def test_track_narrative_cli_command(mock_gnews, mock_tweepy, mock_ai_sentiment):
    """
    Tests that the CLI command runs correctly and prints the output table.
    """
    # --- FIX: Remove the "track" command from the invocation ---
    # Since it's a single-command app, the app IS the command.
    result = runner.invoke(narrative_analyzer_app, ["--track", "test query"])
    # --- END FIX ---

    assert result.exit_code == 0, result.stdout
    assert "Narrative Analysis Summary" in result.stdout
    assert "A Test Article" in result.stdout
    assert "A test tweet" in result.stdout
    # Check for sentiment in the output

    assert "Positive" in result.stdout
