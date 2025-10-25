import pytest
from typer.testing import CliRunner
import json
from unittest.mock import AsyncMock

# The application instance to be tested
from chimera_intel.core.marint import marint_app
# Import the config object to patch it at its source
from chimera_intel.core.config_loader import API_KEYS

runner = CliRunner()


@pytest.fixture(autouse=True)
def mock_api_key_globally(mocker):
    """
    Mocks the API key at the config level (autouse=True)
    to prevent SystemExit(2) when marint_app is imported.
    This fixture runs before all tests in this file.
    """
    mocker.patch.object(API_KEYS, "aisstream_api_key", "fake_key_for_all_tests")


@pytest.fixture
def mock_websockets(mocker):
    """Mocks the websockets.connect call."""
    # This is the mock for the object returned by websockets.connect()
    mock_connect = AsyncMock()

    # Simulate receiving a valid JSON message
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

    # The 'async with' calls __aenter__, which should return
    # the object that will be iterated over ('websocket').
    mock_connect.__aenter__.return_value = mock_connect

    # Add the missing 'send' method to the mock
    mock_connect.send = AsyncMock()

    # Configure mock_connect to be an async iterator by setting its __aiter__ to return self
    # and its __anext__ to yield the desired message and then raise StopAsyncIteration.
    # Note: This technique manually sets the required async iterator protocol attributes.
    # FIX: Change lambda to accept 'self' (the mock object) as the first argument,
    # and return itself to be the async iterator.
    mock_connect.__aiter__ = lambda self: self 
    mock_connect.__anext__ = AsyncMock(side_effect=[
        json.dumps(message),
        StopAsyncIteration # Sentinel to end the async for loop
    ])
    
    return mocker.patch("websockets.connect", return_value=mock_connect)


def test_track_vessel_success(mocker, mock_websockets):
    """
    Tests the track-vessel command with a successful API response.
    """
    # Note: The 'autouse' fixture has already set a fake key,
    # but we can re-patch it here if needed.
    mocker.patch("chimera_intel.core.marint.API_KEYS.aisstream_api_key", "fake_api_key")

    # --- FIX: Pass 'imo' as a positional argument, not an option ---
    result = runner.invoke(marint_app, ["9450635", "--test"])
    # --- END FIX ---

    assert result.exit_code == 0, result.output
    assert "Starting live tracking for vessel with IMO: 9450635..." in result.output
    assert "Latitude: 34.0522" in result.output
    assert "Longitude: -118.2437" in result.output


def test_track_vessel_no_api_key(mocker):
    """
    Tests the track-vessel command when the API key is missing.
    """
    # This mock will override the 'autouse' fixture just for this test
    mocker.patch("chimera_intel.core.marint.API_KEYS.aisstream_api_key", None)

    # --- FIX: Pass 'imo' as a positional argument, not an option ---
    result = runner.invoke(marint_app, ["9450635"])
    # --- END FIX ---

    assert result.exit_code == 1, result.output
    assert "Error: AISSTREAM_API_KEY not found in .env file." in result.output