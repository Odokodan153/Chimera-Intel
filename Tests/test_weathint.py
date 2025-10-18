import pytest
import typer
from typer.testing import CliRunner
from unittest.mock import MagicMock, ANY
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

    # --- FIX: Patch the httpx.Client imported by the weathint module ---

    mocker.patch("chimera_intel.core.weathint.httpx.Client", return_value=mock_client)


def test_get_weather_success(mocker, mock_httpx_client):
    """
    Tests the 'get' command with successful responses from all external APIs.
    """
    # --- Setup Mocks ---

    mocker.patch(
        "chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", "fake_api_key"
    )
    mocker.patch(
        "chimera_intel.core.weathint.get_coordinates",
        return_value={"latitude": 40.7128, "longitude": -74.0060},
    )
    mock_console_print = mocker.patch("chimera_intel.core.weathint.console.print")

    # --- Run Command ---

    result = runner.invoke(weathint_app, ["get", "New York, USA"])

    # --- Assertions ---

    # --- FIX: With the correct httpx mock, the command will succeed (exit_code 0) ---

    assert result.exit_code == 0
    mock_console_print.assert_any_call(
        "[bold cyan]Fetching weather for New York, USA...[/bold cyan]"
    )
    # Check that the Panel object is printed

    mock_console_print.assert_any_call(ANY)


def test_get_weather_no_api_key(mocker):
    """
    Tests that the 'get' command fails gracefully if the OpenWeatherMap API key is missing.
    """
    # --- Setup Mocks ---

    mocker.patch("chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", None)
    mocker.patch(
        "chimera_intel.core.weathint.get_coordinates",
        return_value={"latitude": 0, "longitude": 0},
    )
    mock_console_print = mocker.patch("chimera_intel.core.weathint.console.print")

    # --- Run Command ---

    # --- FIX: Catch the typer.Exit exception to test the print call ---

    with pytest.raises(typer.Exit) as e:
        runner.invoke(weathint_app, ["get", "London, UK"], catch_exceptions=False)
    # --- Assertions ---

    assert e.value.exit_code != 0
    mock_console_print.assert_any_call(
        "[bold red]OpenWeatherMap API key not configured.[/bold red]"
    )


def test_get_weather_location_not_found(mocker):
    """
    Tests the CLI's behavior when the geolocator returns no coordinates.
    """
    # --- Setup Mocks ---

    mocker.patch("chimera_intel.core.weathint.get_coordinates", return_value=None)
    mocker.patch(
        "chimera_intel.core.weathint.API_KEYS.openweathermap_api_key", "fake_api_key"
    )
    mock_console_print = mocker.patch("chimera_intel.core.weathint.console.print")

    # --- Run Command ---

    # --- FIX: Catch the typer.Exit exception to test the print call ---

    with pytest.raises(typer.Exit) as e:
        runner.invoke(weathint_app, ["get", "Atlantis"], catch_exceptions=False)
    # --- Assertions ---

    assert e.value.exit_code != 0
    mock_console_print.assert_any_call(
        "[bold red]Could not find coordinates for Atlantis.[/bold red]"
    )
