import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested

from chimera_intel.core.profile_analyzer import profile_analyzer_app

runner = CliRunner()


@pytest.fixture
def mock_tweepy(mocker):
    """Mocks the tweepy.Client."""
    mock_user = MagicMock()
    mock_user.id = "12345"

    mock_tweet = MagicMock()
    mock_tweet.text = "This is a positive test tweet about #testing and @chimera."
    mock_tweet.entities = {
        "mentions": [{"username": "chimera"}],
        "hashtags": [{"tag": "testing"}],
    }

    mock_client = MagicMock()
    mock_client.get_user.return_value.data = mock_user
    mock_client.get_users_tweets.return_value.data = [mock_tweet]

    return mocker.patch(
        "chimera_intel.core.profile_analyzer.tweepy.Client", return_value=mock_client
    )


@pytest.fixture
def mock_ai_core(mocker):
    """Mocks the AI core functions."""
    mocker.patch(
        "chimera_intel.core.profile_analyzer.perform_sentiment_analysis",
        return_value="Positive",
    )
    mocker.patch(
        "chimera_intel.core.profile_analyzer.perform_generative_task",
        return_value="The user frequently discusses testing and Chimera.",
    )


def test_run_profile_analysis_success(mock_tweepy, mock_ai_core, mocker):
    """
    Tests the full run_profile_analysis command with successful API responses.
    """
    mocker.patch(
        "chimera_intel.core.profile_analyzer.API_KEYS.twitter_bearer_token",
        "fake_token",
    )

    result = runner.invoke(
        profile_analyzer_app,
        ["run", "testuser", "--platform", "twitter"],
    )

    assert result.exit_code == 0
    assert "AI Summary of Key Themes" in result.stdout
    assert "The user frequently discusses testing" in result.stdout
    assert "Sentiment Analysis" in result.stdout
    assert "Positive: 1" in result.stdout
    assert "Top 5 Mentions" in result.stdout
    assert "@chimera" in result.stdout
    assert "Top 5 Hashtags" in result.stdout
    assert "#testing" in result.stdout


def test_run_profile_analysis_user_not_found(mocker):
    """
    Tests the command when the specified Twitter user is not found.
    """
    mocker.patch(
        "chimera_intel.core.profile_analyzer.API_KEYS.twitter_bearer_token",
        "fake_token",
    )

    mock_client = MagicMock()
    mock_client.get_user.return_value.data = None  # Simulate user not found
    mocker.patch(
        "chimera_intel.core.profile_analyzer.tweepy.Client", return_value=mock_client
    )

    result = runner.invoke(
        profile_analyzer_app,
        ["run", "nonexistentuser"],
    )

    assert result.exit_code == 1
    assert "Error: User 'nonexistentuser' not found." in result.stdout
