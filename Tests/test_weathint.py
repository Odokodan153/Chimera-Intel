import pytest
from typer.testing import CliRunner
import httpx

# The application instance to be tested

from chimera_intel.core.weathint import weathint_app

runner = CliRunner()


@pytest.fixture
def mock_geolocator(mocker):
    """Mocks the geopy.geocoders.Nominatim call."""
    mock_location = mocker.MagicMock()
    mock_location.latitude = 37.3318
    mock_location.longitude = -122.0312

    mock_geocode = mocker.MagicMock(return_value=mock_location)
    mocker.patch("geopy.geocoders.Nominatim.geocode", new=mock_geocode)
    return mock_geocode


def test_risk_assessment_success(mocker, mock_geolocator):
    """
    Tests the risk-assessment command with successful API responses.
    """
    # Mock the API_KEYS to provide a fake API key

    mocker.patch(
        "chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", "fake_api_key"
    )

    # Mock the httpx client response

    mock_response = httpx.Response(
        200,
        json={
            "weather": [{"main": "Clear"}],
            "main": {"temp": 25.5},
            "wind": {"speed": 3.5},
        },
    )
    mocker.patch("httpx.Client.get", return_value=mock_response)

    result = runner.invoke(
        weathint_app,
        [
            "risk-assessment",
            "--location",
            "1 Infinite Loop, Cupertino, CA",
            "--peril",
            "wildfire",
        ],
    )

    assert result.exit_code == 0
    assert "Performing 'wildfire' risk assessment" in result.stdout
    assert "Coordinates found: Latitude=37.3318" in result.stdout
    assert "Current Weather: Clear" in result.stdout
    assert "Temperature: 25.5°C" in result.stdout


def test_risk_assessment_no_api_key(mocker, mock_geolocator):
    """
    Tests the risk-assessment command when the API key is missing.
    """
    mocker.patch("chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", None)

    result = runner.invoke(
        weathint_app,
        ["risk-assessment", "--location", "some address", "--peril", "flood"],
    )

    assert result.exit_code == 1
    assert (
        "Configuration Error: OPENWEATHERMAP_API_KEY not found in .env file."
        in result.stdout
    )
