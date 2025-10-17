from typer.testing import CliRunner
from unittest.mock import patch

# Import the application instance and the SWOTAnalysisResult schema

from chimera_intel.core.profile_analyzer import profile_analyzer_app
from chimera_intel.core.schemas import SWOTAnalysisResult

runner = CliRunner()


@patch("chimera_intel.core.profile_analyzer.get_user_timeline")
@patch("chimera_intel.core.profile_analyzer.generate_swot_from_data")
@patch("chimera_intel.core.profile_analyzer.API_KEYS")
def test_analyze_twitter_profile_success(
    mock_api_keys, mock_generate_swot, mock_get_timeline
):
    """
    Tests the successful run of a Twitter profile analysis.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_api_keys.twitter_bearer_token = "dummy_token"
    mock_get_timeline.return_value = [
        {"full_text": "Test tweet 1", "entities": {"user_mentions": [], "hashtags": []}}
    ]
    mock_generate_swot.return_value = SWOTAnalysisResult(
        analysis_text="Behavioral profile summary.", error=None
    )

    # --- Run Command ---

    result = runner.invoke(profile_analyzer_app, ["twitter", "TestUser"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Analyzing Twitter profile for @TestUser..." in result.stdout
    assert "Behavioral profile summary." in result.stdout


@patch("chimera_intel.core.profile_analyzer.get_user_timeline")
@patch("chimera_intel.core.profile_analyzer.API_KEYS")
def test_analyze_twitter_profile_no_tweets(mock_api_keys, mock_get_timeline):
    """
    Tests the command's behavior when no tweets are found for the user.
    """
    # --- Setup Mocks ---

    mock_api_keys.twitter_bearer_token = "dummy_token"
    mock_get_timeline.return_value = []  # Simulate no tweets found

    # --- Run Command ---

    result = runner.invoke(profile_analyzer_app, ["twitter", "notweetsuser"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "No tweets found for this user." in result.stdout


@patch("chimera_intel.core.profile_analyzer.API_KEYS")
def test_analyze_twitter_profile_no_twitter_api_key(mock_api_keys):
    """
    Tests that the command fails gracefully if the Twitter API key is not configured.
    """
    # --- Setup Mock ---

    mock_api_keys.twitter_bearer_token = None  # Simulate missing API key

    # --- Run Command ---

    result = runner.invoke(profile_analyzer_app, ["twitter", "any-target"])

    # --- Assertions ---

    assert result.exit_code == 1
    assert "Error: Twitter Bearer Token is not configured." in result.stdout
