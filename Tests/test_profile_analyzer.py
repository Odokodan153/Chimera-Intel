import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import tweepy

# The application instance to be tested
from chimera_intel.core.profile_analyzer import profile_analyzer_app
from chimera_intel.core.ai_core import AIResult

runner = CliRunner()


@pytest.fixture
def mock_tweepy_api(mocker):
    """Mocks the tweepy.API object and its user_timeline method."""
    # This dictionary simulates the JSON response from the Twitter API
    mock_tweet_json = {
        "full_text": "This is a test tweet about #python and @chimera_intel.",
        "entities": {
            "user_mentions": [{"screen_name": "chimera_intel"}],
            "hashtags": [{"text": "python"}],
        },
    }
    
    # The API returns a list of these tweet objects
    mock_tweet_obj = MagicMock()
    mock_tweet_obj._json = mock_tweet_json

    # Mock the tweepy.API instance
    mock_api = MagicMock()
    mock_api.user_timeline.return_value = [mock_tweet_obj]
    
    # Patch the OAuth handler and the API object itself
    mocker.patch("chimera_intel.core.profile_analyzer.tweepy.OAuth2BearerHandler")
    mocker.patch("chimera_intel.core.profile_analyzer.tweepy.API", return_value=mock_api)
    
    return mock_api


@pytest.fixture
def mock_ai_core(mocker):
    """Mocks the generate_swot_from_data function in the ai_core module."""
    mock_ai_result = AIResult(
        analysis_text="The user shows a strong interest in Python programming and the Chimera Intel platform.",
        error=None,
    )
    return mocker.patch(
        "chimera_intel.core.profile_analyzer.generate_swot_from_data",
        return_value=mock_ai_result,
    )


def test_analyze_twitter_profile_success(mock_tweepy_api, mock_ai_core, mocker):
    """
    Tests the full 'twitter' command with successful responses from all APIs.
    """
    # Mock the necessary API keys to pass the configuration checks
    mocker.patch("chimera_intel.core.profile_analyzer.API_KEYS.twitter_bearer_token", "fake_token")
    mocker.patch("chimera_intel.core.profile_analyzer.API_KEYS.google_api_key", "fake_key")

    # Invoke the CLI command
    result = runner.invoke(profile_analyzer_app, ["twitter", "testuser"])

    # --- Assertions ---
    assert result.exit_code == 0
    # Check for the initial analysis message
    assert "Analyzing Twitter profile for @testuser..." in result.stdout
    # Check for the activity summary panel
    assert "Activity Summary" in result.stdout
    assert "Most Mentioned" in result.stdout
    assert "'chimera_intel', 1" in result.stdout
    # Check for the AI-powered behavioral profile panel
    assert "AI Behavioral Profile" in result.stdout
    assert "The user shows a strong interest in Python programming" in result.stdout


def test_analyze_twitter_profile_no_tweets(mock_tweepy_api, mocker):
    """
    Tests the command's behavior when a user has no tweets.
    """
    # Mock the API keys
    mocker.patch("chimera_intel.core.profile_analyzer.API_KEYS.twitter_bearer_token", "fake_token")
    mocker.patch("chimera_intel.core.profile_analyzer.API_KEYS.google_api_key", "fake_key")
    
    # Configure the mock to return an empty list, simulating no tweets found
    mock_tweepy_api.user_timeline.return_value = []

    # Invoke the command
    result = runner.invoke(profile_analyzer_app, ["twitter", "no_tweets_user"])

    # --- Assertions ---
    assert result.exit_code == 0
    assert "No tweets found for this user." in result.stdout
    # Ensure no analysis panels are displayed
    assert "Activity Summary" not in result.stdout
    assert "AI Behavioral Profile" not in result.stdout


def test_analyze_twitter_profile_api_error(mock_tweepy_api, mocker):
    """
    Tests how the command handles a Twitter API error.
    """
    # Mock the API keys
    mocker.patch("chimera_intel.core.profile_analyzer.API_KEYS.twitter_bearer_token", "fake_token")
    
    # Configure the mock to raise a TweepyException
    mock_tweepy_api.user_timeline.side_effect = tweepy.errors.TweepyException(
        "User not found."
    )

    # Invoke the command
    result = runner.invoke(profile_analyzer_app, ["twitter", "nonexistentuser"])
    
    # --- Assertions ---
    assert result.exit_code == 0 # The app handles the error gracefully and exits 0
    assert "Twitter API Error:" in result.stdout
    assert "User not found." in result.stdout
    assert "No tweets found for this user." in result.stdout