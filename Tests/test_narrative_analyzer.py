import pytest
from typer.testing import CliRunner
import httpx
import tweepy

# The application instance to be tested

from chimera_intel.core.narrative_analyzer import narrative_analyzer_app

runner = CliRunner()


@pytest.fixture
def mock_gnews(mocker):
    """Mocks the httpx call to GNews."""
    mock_response = httpx.Response(
        200,
        json={
            "articles": [
                {
                    "title": "MegaCorp Issues Major Recall",
                    "source": {"name": "News Network 1"},
                }
            ]
        },
    )
    return mocker.patch("httpx.Client.get", return_value=mock_response)


@pytest.fixture
def mock_tweepy(mocker):
    """Mocks the tweepy.Client call."""
    mock_tweet = mocker.MagicMock()
    mock_tweet.text = "This is a tweet about the recall."
    mock_tweet.author_id = "12345"

    mock_response = mocker.MagicMock()
    mock_response.data = [mock_tweet]

    mock_client = mocker.MagicMock()
    mock_client.search_recent_tweets.return_value = mock_response
    return mocker.patch("tweepy.Client", return_value=mock_client)


@pytest.fixture
def mock_ai_sentiment(mocker):
    """Mocks the AI core sentiment analysis call."""
    return mocker.patch(
        "chimera_intel.core.narrative_analyzer.perform_sentiment_analysis",
        return_value="Negative",
    )


def test_track_narrative_success(mocker, mock_gnews, mock_tweepy, mock_ai_sentiment):
    """
    Tests the track-narrative command with successful API responses.
    """
    mocker.patch(
        "chimera_intel.core.narrative_analyzer.API_KEYS.gnews_api_key", "fake_gnews_key"
    )
    mocker.patch(
        "chimera_intel.core.narrative_analyzer.API_KEYS.twitter_bearer_token",
        "fake_twitter_token",
    )

    result = runner.invoke(
        narrative_analyzer_app, ["track", "--track", "MegaCorp Recall"]
    )

    assert result.exit_code == 0
    assert "Tracking narrative: 'MegaCorp Recall'" in result.stdout
    assert "News Network 1" in result.stdout
    assert "Tweet by User ID: 12345" in result.stdout
    assert "Negative" in result.stdout


def test_track_narrative_no_gnews_key(mocker):
    """
    Tests the command when the GNews API key is missing.
    """
    mocker.patch("chimera_intel.core.narrative_analyzer.API_KEYS.gnews_api_key", None)

    result = runner.invoke(narrative_analyzer_app, ["track", "--track", "test"])

    assert result.exit_code == 1
    assert "GNEWS_API_KEY not found in .env file." in result.stdout
