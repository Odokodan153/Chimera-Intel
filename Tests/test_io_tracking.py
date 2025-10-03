import pytest
from typer.testing import CliRunner
import httpx

# The application instance to be tested

from chimera_intel.core.io_tracking import io_tracking_app

runner = CliRunner()


def test_track_influence_success(mocker):
    """
    Tests the track-influence command with a successful API response.
    """
    # Mock the API_KEYS to provide a fake GNews API key

    mocker.patch(
        "chimera_intel.core.io_tracking.API_KEYS.gnews_api_key", "fake_gnews_key"
    )

    # Mock the httpx client response

    mock_response = httpx.Response(
        200,
        json={
            "articles": [
                {
                    "title": "Rumors of Failure Swirl Around New Product",
                    "source": {"name": "Tech News Today"},
                },
                {
                    "title": "Product Failure Claims Debunked by Company",
                    "source": {"name": "Business Insider"},
                },
            ]
        },
    )
    mocker.patch("httpx.Client.get", return_value=mock_response)

    result = runner.invoke(
        io_tracking_app, ["track"], input="rumors of product failure\n"
    )

    assert result.exit_code == 0
    assert (
        "Tracking influence campaign for narrative: 'rumors of product failure'"
        in result.stdout
    )
    assert "Found 2 news articles related to the narrative." in result.stdout
    assert "Source: Tech News Today" in result.stdout


def test_track_influence_no_api_key(mocker):
    """
    Tests the track-influence command when the API key is missing.
    """
    mocker.patch("chimera_intel.core.io_tracking.API_KEYS.gnews_api_key", None)

    result = runner.invoke(io_tracking_app, ["track"], input="some narrative\n")

    assert result.exit_code == 1
    assert "Configuration Error: GNEWS_API_KEY not found in .env file." in result.stdout
