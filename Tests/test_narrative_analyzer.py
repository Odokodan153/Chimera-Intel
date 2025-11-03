import pytest
from unittest.mock import patch, MagicMock
from chimera_intel.core.narrative_analyzer import (
    narrative_analyzer_app,
)
from typing import ANY
from chimera_intel.core.schemas import SentimentResult, AIResult
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

@patch("chimera_intel.core.narrative_analyzer.fetch_news")
@patch("chimera_intel.core.narrative_analyzer.fetch_tweets")
@patch("chimera_intel.core.narrative_analyzer.analyze_sentiment")
def test_track_narrative(mock_sentiment, mock_tweets, mock_news):
    # Mock API returns
    mock_news.return_value = [
        {"source": {"name": "News Site"}, "title": "Test Article"}
    ]
    mock_tweet_obj = MagicMock()
    mock_tweet_obj.author_id = "123"
    mock_tweet_obj.text = "Test Tweet"
    mock_tweets.return_value = [mock_tweet_obj]
    
    # Mock AI sentiment
    mock_sentiment.return_value = SentimentResult(label="Positive", score=0.9)
    
    result = runner.invoke(narrative_analyzer_app, ["track", "--track", "Test Topic"])
    
    assert result.exit_code == 0
    assert "Narrative Analysis Summary" in result.stdout
    assert "Test Article" in result.stdout
    assert "Test Tweet" in result.stdout
    assert "Positive" in result.stdout


@patch("chimera_intel.core.narrative_analyzer.track_narrative")
@patch("chimera_intel.core.narrative_analyzer.generate_swot_from_data")
def test_map_influence(mock_ai, mock_track):
    """
    Tests the new 'map' command.
    """
    # 1. Mock the return from the 'track' function it calls
    mock_track_data = [
        {"source": "News", "type": "News", "content": "Article 1", "sentiment": "Positive"},
        {"source": "Twitter", "type": "Tweet", "content": "Tweet 1", "sentiment": "Negative"},
    ]
    mock_track.return_value = mock_track_data

    # 2. Mock the AI response for the influence report
    report_text = "1. Key Narratives: Story A is dominant\n2. Key Influencers: News"
    mock_ai.return_value = AIResult(analysis_text=report_text, error=None)

    # 3. Run the command
    result = runner.invoke(
        narrative_analyzer_app,
        ["map", "--track", "Test Topic"]
    )

    # 4. Assert results
    assert result.exit_code == 0
    # Check that it first calls 'track'
    mock_track.assert_called_once_with(query="Test Topic")
    
    # Check that it then calls the AI
    mock_ai.assert_called_once_with(ANY, ANY)
    assert "You are an expert information operations" in mock_ai.call_args[0][0]
    assert "Article 1" in mock_ai.call_args[0][0]
    assert "Tweet 1" in mock_ai.call_args[0][0]

    # Check that the final report is printed
    assert "Mapping influence and information operations" in result.stdout
    assert "Narrative Influence Map" in result.stdout
    assert "Story A is dominant" in result.stdout

@patch("chimera_intel.core.narrative_analyzer.track_narrative")
def test_map_influence_no_data(mock_track):
    """
    Tests that 'map' exits gracefully if 'track' returns no data.
    """
    mock_track.return_value = []
    
    result = runner.invoke(
        narrative_analyzer_app,
        ["map", "--track", "Empty Topic"]
    )
    
    assert result.exit_code != 0  # It should exit
    assert "No tracking results found. Cannot map influence." in result.stdoutс
