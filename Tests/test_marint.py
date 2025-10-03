import pytest
from typer.testing import CliRunner
import json
import asyncio
from unittest.mock import AsyncMock

# The application instance to be tested

from chimera_intel.core.marint import marint_app

runner = CliRunner()


@pytest.fixture
def mock_websockets(mocker):
    """Mocks the websockets.connect call."""
    mock_websocket = AsyncMock()

    # Simulate receiving a valid JSON message

    async def mock_recv():
        message = {
            "MessageType": "PositionReport",
            "Message": {
                "PositionReport": {
                    "ImoNumber": "9450635",
                    "Latitude": 34.0522,
                    "Longitude": -118.2437,
                    "Sog": 15.5,
                    "Cog": 120.0,
                }
            },
        }
        yield json.dumps(message)

    # Configure the mock context manager

    mock_websocket.__aenter__.return_value.recv = mock_recv
    mock_websocket.__aenter__.return_value.__aiter__.return_value = mock_recv()

    return mocker.patch("websockets.connect", return_value=mock_websocket)


def test_track_vessel_success(mocker, mock_websockets):
    """
    Tests the track-vessel command with a successful API response.
    """
    # Mock the API_KEYS to provide a fake API key

    mocker.patch("chimera_intel.core.marint.API_KEYS.aisstream_api_key", "fake_api_key")

    # Mock asyncio.run to prevent the infinite loop in the test

    mocker.patch(
        "asyncio.run",
        side_effect=lambda coro: asyncio.get_event_loop().run_until_complete(coro),
    )

    # We run the command with input to simulate the user prompt

    result = runner.invoke(marint_app, ["track-vessel"], input="9450635\n")

    assert result.exit_code == 0
    assert "Starting live tracking for vessel with IMO: 9450635..." in result.stdout
    assert "Latitude: 34.0522" in result.stdout
    assert "Longitude: -118.2437" in result.stdout


def test_track_vessel_no_api_key(mocker):
    """
    Tests the track-vessel command when the API key is missing.
    """
    # Mock the API_KEYS to return None for the API key

    mocker.patch("chimera_intel.core.marint.API_KEYS.aisstream_api_key", None)

    result = runner.invoke(marint_app, ["track-vessel"], input="9450635\n")

    assert result.exit_code == 0
    assert "Error: AISSTREAM_API_KEY not found in .env file." in result.stdout
