import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import typer 
from chimera_intel.core.profile_analyzer import profile_analyzer_app
from chimera_intel.core.schemas import SWOTAnalysisResult

app = typer.Typer()
app.add_typer(profile_analyzer_app)

runner = CliRunner()


@pytest.fixture
def mock_api_keys(mocker):
    """Mocks the API_KEYS object."""
    mock_keys = MagicMock()
    mock_keys.google_api_key = "fake_google_key"
    mocker.patch("chimera_intel.core.profile_analyzer.API_KEYS", mock_keys)
    return mock_keys


@pytest.fixture
def mock_snscrape(mocker):
    """Mocks the snscrape.modules.twitter.TwitterSearchScraper."""
    mock_scraper = MagicMock()
    mock_tweet = MagicMock()
    mock_tweet.rawContent = "This is a test tweet."
    mock_scraper.return_value.get_items.return_value = [mock_tweet] * 5
    mocker.patch(
        "chimera_intel.core.profile_analyzer.sntwitter.TwitterSearchScraper",
        mock_scraper,
    )
    return mock_scraper


@patch("chimera_intel.core.profile_analyzer.generate_swot_from_data")
def test_analyze_twitter_profile_success(
    mock_generate_swot, mock_api_keys, mock_snscrape
):
    """Tests successful analysis of a Twitter profile."""
    mock_generate_swot.return_value = SWOTAnalysisResult(
        analysis_text="Positive sentiment.", error=None
    )

    result = runner.invoke(
        app, ["profile", "analyze-twitter", "testuser", "--limit", "10"]
    )

    assert result.exit_code == 0
    assert "Analyzing 5 tweets for @testuser..." in result.stdout
    assert "Behavioral Analysis (SWOT) for @testuser" in result.stdout
    assert "Positive sentiment." in result.stdout


@patch("chimera_intel.core.profile_analyzer.generate_swot_from_data")
def test_analyze_twitter_profile_no_tweets(
    mock_generate_swot, mock_api_keys, mock_snscrape
):
    """Tests analysis when the user has no tweets."""
    mock_snscrape.return_value.get_items.return_value = []  # No tweets

    result = runner.invoke(
        app, ["profile", "analyze-twitter", "notweetsuser", "--limit", "10"]
    )

    assert result.exit_code == 0
    assert "No tweets found for @notweetsuser." in result.stdout
    assert "Behavioral Analysis" not in result.stdout


def test_analyze_twitter_profile_no_twitter_api_key(mock_api_keys):
    """Tests failure when the Google API key (for AI analysis) is missing."""
    mock_api_keys.google_api_key = None  # Simulate missing key

    result = runner.invoke(
        app, ["profile", "analyze-twitter", "anyuser", "--limit", "10"]
    )

    assert result.exit_code == 1
    assert "Error: Google API key is not configured." in result.stdout
