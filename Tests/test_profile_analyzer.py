import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import typer
from chimera_intel.core.profile_analyzer import profile_analyzer_app
from chimera_intel.core.schemas import SWOTAnalysisResult

app = typer.Typer()
app.add_typer(profile_analyzer_app, name="profile")

runner = CliRunner()


@pytest.fixture
def mock_api_keys(mocker):
    """Mocks the API_KEYS object."""
    mock_keys = MagicMock()
    mock_keys.google_api_key = "fake_google_key"
    mock_keys.twitter_bearer_token = "fake_twitter_token"
    mocker.patch("chimera_intel.core.profile_analyzer.API_KEYS", mock_keys)
    return mock_keys


@pytest.fixture
def mock_tweepy_api(mocker):
    """Mocks the tweepy.API."""
    mock_api_class = mocker.patch("chimera_intel.core.profile_analyzer.tweepy.API")
    mock_api_instance = mock_api_class.return_value

    # Create mock tweet objects
    mock_tweet = MagicMock()
    mock_tweet._json = {
        "full_text": "This is a test tweet about #testing.",
        "entities": {
            "user_mentions": [{"screen_name": "mockuser"}],
            "hashtags": [{"text": "testing"}],
        },
    }

    # Configure user_timeline to return a list of these mocks
    mock_api_instance.user_timeline.return_value = [mock_tweet] * 5

    # Patch the bearer token handler as well
    mocker.patch("chimera_intel.core.profile_analyzer.tweepy.OAuth2BearerHandler")

    return mock_api_instance


@patch("chimera_intel.core.profile_analyzer.generate_swot_from_data")
def test_analyze_twitter_profile_success(
    mock_generate_swot, mock_api_keys, mock_tweepy_api
):
    """Tests successful analysis of a Twitter profile."""
    mock_generate_swot.return_value = SWOTAnalysisResult(
        analysis_text="Positive sentiment.", error=None
    )

    result = runner.invoke(app, ["profile", "twitter", "testuser", "--count", "10"])

    assert result.exit_code == 0
    assert "Analyzing Twitter profile for @testuser" in result.stdout
    assert "Activity Summary" in result.stdout
    assert "Most Mentioned: [('mockuser', 5)]" in result.stdout
    assert "Most Used Hashtags: [('testing', 5)]" in result.stdout
    assert "AI Behavioral Profile" in result.stdout
    assert "Positive sentiment." in result.stdout
    # Check that tweepy was called with the correct args
    mock_tweepy_api.user_timeline.assert_called_with(
        screen_name="testuser", count=10, tweet_mode="extended"
    )


@patch("chimera_intel.core.profile_analyzer.generate_swot_from_data")
def test_analyze_twitter_profile_no_tweets(
    mock_generate_swot, mock_api_keys, mock_tweepy_api
):
    """Tests analysis when the user has no tweets."""
    mock_tweepy_api.user_timeline.return_value = []  # No tweets

    result = runner.invoke(app, ["profile", "twitter", "notweetsuser", "--count", "10"])

    assert result.exit_code == 0
    assert "No tweets found for this user." in result.stdout
    assert "AI Behavioral Profile" not in result.stdout


def test_analyze_twitter_profile_no_google_key(mock_api_keys, mock_tweepy_api):
    """Tests failure when the Google API key (for AI analysis) is missing."""
    mock_api_keys.google_api_key = None  # Simulate missing key

    result = runner.invoke(app, ["profile", "twitter", "anyuser", "--count", "10"])

    # The command should still succeed (exit_code 0)
    assert result.exit_code == 0
    # It should fetch tweets successfully
    assert "Activity Summary" in result.stdout
    # But it should print an error for the AI part
    assert "Error: Google API key not configured." in result.stdout
    # And it should NOT show the AI profile panel
    assert "AI Behavioral Profile" not in result.stdout


def test_analyze_twitter_profile_no_twitter_token(mock_api_keys):
    """Tests failure when the Twitter Bearer Token is missing."""
    mock_api_keys.twitter_bearer_token = None  # Simulate missing key

    result = runner.invoke(app, ["profile", "twitter", "anyuser", "--count", "10"])

    # The command should fail with exit_code 1
    assert result.exit_code == 1
    assert "Error: Twitter Bearer Token is not configured." in result.stdout
