import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
import httpx

# The application instance to be tested

from chimera_intel.core.weathint import weathint_app, console

runner = CliRunner()


@pytest.fixture
def mock_geolocator(mocker):
    """Mocks the geopy.geocoders.Nominatim to return a fixed coordinate."""
    mock_location = MagicMock()
    mock_location.latitude = 40.7128
    mock_location.longitude = -74.0060

    # We patch the geocode method on the Nominatim class instance

    mocker.patch("geopy.geocoders.Nominatim.geocode", return_value=mock_location)


@pytest.fixture
def mock_httpx_client(mocker):
    """Mocks the httpx.Client to return a fixed weather JSON response."""
    # This is a sample response from the OpenWeatherMap API

    mock_weather_data = {
        "weather": [{"main": "Clouds", "description": "overcast clouds"}],
        "main": {"temp": 18.5, "feels_like": 18.2},
        "wind": {"speed": 5.1},
    }

    # Mock the response object that httpx would return

    mock_response = httpx.Response(200, json=mock_weather_data)

    # We mock the context manager `httpx.Client` and its `get` method

    mock_client = MagicMock()
    mock_client.__enter__.return_value.get.return_value = mock_response
    mocker.patch("httpx.Client", return_value=mock_client)


def test_get_weather_success(mocker, mock_geolocator, mock_httpx_client):
    """
    Tests the 'get' command with successful responses from all external APIs.
    """
    # --- Setup Mocks ---
    # Provide a fake API key so the configuration check passes

    mocker.patch(
        "chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", "fake_api_key"
    )

    # --- Run Command ---

    result = runner.invoke(weathint_app, ["get", "New York, USA"])

    # --- Assertions ---

    assert result.exit_code == 0
    # Check for the initial status message

    assert "Fetching weather for New York, USA..." in result.stdout
    # Check that the final report panel is displayed with the correct data

    assert "Current Weather in New York, USA" in result.stdout
    assert "Weather: Clouds (overcast clouds)" in result.stdout
    assert "Temperature: 18.5°C (Feels like: 18.2°C)" in result.stdout
    assert "Wind Speed: 5.1 m/s" in result.stdout


def test_get_weather_no_api_key(mocker):
    """
    Tests that the 'get' command fails gracefully if the OpenWeatherMap API key is missing.
    """
    # --- Setup Mock ---
    # Simulate the API key being absent

    mocker.patch("chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", None)
    # Since get_coordinates is called before the API key check, we need to mock it.

    mocker.patch(
        "chimera_intel.core.weathint.get_coordinates",
        return_value={"latitude": 0, "longitude": 0},
    )

    # --- Run Command ---

    with patch.object(console, "print") as mock_print:
        result = runner.invoke(weathint_app, ["get", "London, UK"])
        mock_print.assert_any_call(
            "[bold red]OpenWeatherMap API key not configured.[/bold red]"
        )
    # Ensure no weather report is printed

    assert "Current Weather in London, UK" not in result.stdout


def test_get_weather_location_not_found(mocker):
    """
    Tests the CLI's behavior when the geolocator returns no coordinates.
    """
    # --- Setup Mock ---
    # This time, we mock the function that calls the geolocator

    mocker.patch("chimera_intel.core.weathint.get_coordinates", return_value=None)
    mocker.patch(
        "chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", "fake_api_key"
    )

    # --- Run Command ---

    with patch.object(console, "print") as mock_print:
        runner.invoke(weathint_app, ["get", "Atlantis"])
        mock_print.assert_any_call(
            "[bold red]Could not find coordinates for Atlantis.[/bold red]"
        )
