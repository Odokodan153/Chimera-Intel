from typer.testing import CliRunner
import httpx
from unittest.mock import patch, MagicMock

# Import API_KEYS from the config loader first
from chimera_intel.core.config_loader import API_KEYS

# --- FIX APPLIED ---
# Patch the API key *before* importing the io_tracking_app.
# This ensures the Typer app initializes correctly at import time,
# resolving the exit code 2 errors.
with patch.object(API_KEYS, "gnews_api_key", "fake_key_for_import"):
    from chimera_intel.core.io_tracking import io_tracking_app
# --- END FIX ---

runner = CliRunner()


@patch("chimera_intel.core.io_tracking.search_reddit_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_twitter_narrative", return_value=[])
@patch("chimera_intel.core.io_tracking.search_news_narrative")
def test_track_influence_success(
    mock_search_news, mock_search_twitter, mock_search_reddit
):
    """
    Tests the track-influence command with a successful API response.
    """
    # Arrange

    mock_search_news.return_value = [
        {
            "title": "Rumors of Failure Swirl Around New Product",
            "source": {"name": "Tech News Today"},
            "url": "http://example.com/news1",
        },
        {
            "title": "Product Failure Claims Debunked by Company",
            "source": {"name": "Business Insider"},
            "url": "http://example.com/news2",
        },
    ]

    # Act

    result = runner.invoke(
        io_tracking_app, ["track", "--narrative", "rumors of product failure"]
    )

    # Assert

    assert result.exit_code == 0
    assert (
        "Tracking influence campaign for narrative: 'rumors of product failure'"
        in result.output
    )
    assert "Found 2 news articles related to the narrative." in result.output
    assert "Tech News Today" in result.output
    assert "Business Insider" in result.output


def test_track_influence_no_api_key():
    """
    Tests the track-influence command when the API key is missing.
    """
    # Arrange
    # We patch the key to None *within* this test's context
    # to override the global 'fake_key_for_import' and test the error case.
    with patch("chimera_intel.core.io_tracking.API_KEYS.gnews_api_key", None):
        # Act

        result = runner.invoke(
            io_tracking_app, ["track", "--narrative", "some narrative"]
        )

    # Assert

    assert result.exit_code == 1
    assert "Configuration Error: GNEWS_API_KEY not found in .env file." in result.output


@patch("chimera_intel.core.io_tracking.search_news_narrative")
def test_track_influence_api_error(mock_search_news):
    """
    Tests the track-influence command when the GNews API returns an error.
    """
    # Arrange
    # The API key is already set by the import-level patch,
    # so we only need to mock the side effect.
    mock_search_news.side_effect = httpx.HTTPStatusError(
        "API Error", request=MagicMock(), response=httpx.Response(500)
    )

    # Act

    result = runner.invoke(io_tracking_app, ["track", "--narrative", "api failure"])

    # Assert

    assert result.exit_code == 1
    assert "API Error: Failed to fetch data. Status code: 500" in result.output