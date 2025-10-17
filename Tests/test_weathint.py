import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock
import httpx

# The application instance to be tested

from chimera_intel.core.weathint import weathint_app

runner = CliRunner()


@pytest.fixture
def mock_httpx_client(mocker):
    """Mocks the httpx.Client to return a fixed weather JSON response."""
    mock_weather_data = {
        "weather": [{"main": "Clouds", "description": "overcast clouds"}],
        "main": {"temp": 18.5, "feels_like": 18.2},
        "wind": {"speed": 5.1},
    }
    mock_response = httpx.Response(200, json=mock_weather_data)
    mock_client = MagicMock()
    mock_client.__enter__.return_value.get.return_value = mock_response
    mocker.patch("httpx.Client", return_value=mock_client)


def test_get_weather_success(mocker, mock_httpx_client):
    """
    Tests the 'get' command with successful responses from all external APIs.
    """
    # --- Setup Mocks ---
    # Mock the API key and the coordinates function to avoid external calls

    mocker.patch(
        "chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", "fake_api_key"
    )
    mocker.patch(
        "chimera_intel.core.weathint.get_coordinates",
        return_value={"latitude": 40.7128, "longitude": -74.0060},
    )

    # --- Run Command ---

    result = runner.invoke(weathint_app, ["get", "New York, USA"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Fetching weather for New York, USA..." in result.stdout
    assert "Current Weather in New York, USA" in result.stdout
    assert "Weather: Clouds (overcast clouds)" in result.stdout
    assert "Temperature: 18.5°C (Feels like: 18.2°C)" in result.stdout
    assert "Wind Speed: 5.1 m/s" in result.stdout


def test_get_weather_no_api_key(mocker):
    """
    Tests that the 'get' command fails gracefully if the OpenWeatherMap API key is missing.
    """
    # --- Setup Mocks ---

    mocker.patch("chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", None)
    # Mock get_coordinates to allow the function to proceed to the API key check

    mocker.patch(
        "chimera_intel.core.weathint.get_coordinates",
        return_value={"latitude": 0, "longitude": 0},
    )
    # Patch the console print function

    mock_console_print = mocker.patch("chimera_intel.core.weathint.console.print")

    # --- Run Command ---

    result = runner.invoke(weathint_app, ["get", "London, UK"])

    # --- Assertions ---
    # The command should exit with a non-zero code

    assert result.exit_code != 0
    # Check that the correct error message was printed

    mock_console_print.assert_any_call(
        "[bold red]OpenWeatherMap API key not configured.[/bold red]"
    )
    # Ensure no weather report is printed

    assert "Current Weather in London, UK" not in result.stdout


def test_get_weather_location_not_found(mocker):
    """
    Tests the CLI's behavior when the geolocator returns no coordinates.
    """
    # --- Setup Mocks ---
    # Mock get_coordinates to simulate failure

    mocker.patch("chimera_intel.core.weathint.get_coordinates", return_value=None)
    mocker.patch(
        "chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", "fake_api_key"
    )
    # Patch the console print function

    mock_console_print = mocker.patch("chimera_intel.core.weathint.console.print")

    # --- Run Command ---

    result = runner.invoke(weathint_app, ["get", "Atlantis"])

    # --- Assertions ---

    assert result.exit_code != 0
    mock_console_print.assert_any_call(
        "[bold red]Could not find coordinates for Atlantis.[/bold red]"
    )
