import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock

# You need to import 'app' from your CLI file

from chimera_intel.cli import app

runner = CliRunner()

# --- Tests for basic commands ---


def test_main_app_help():
    """Tests if the main --help command works."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage: main [OPTIONS] COMMAND [ARGS]..." in result.stdout
    assert "scan" in result.stdout
    assert "defensive" in result.stdout


# --- Tests for the 'scan' group ---


@patch("chimera_intel.cli.gather_footprint_data", new_callable=AsyncMock)
def test_scan_footprint_success(mock_gather_footprint):
    """Tests a successful 'scan footprint' command."""
    # We simulate that the function returns an empty Pydantic model to avoid real requests

    mock_gather_footprint.return_value.model_dump.return_value = {
        "domain": "example.com",
        "footprint": {},
    }

    result = runner.invoke(app, ["scan", "footprint", "run", "example.com"])
    assert result.exit_code == 0
    assert "Footprint scan complete for example.com" in result.stdout


def test_scan_footprint_invalid_domain():
    """Tests 'scan footprint' with an invalid domain."""
    result = runner.invoke(app, ["scan", "footprint", "run", "invalid-domain"])
    assert result.exit_code == 1
    assert "is not a valid domain format" in result.stdout


# --- Tests for the 'defensive' group ---


@patch("chimera_intel.core.defensive.check_hibp_breaches")
@patch("chimera_intel.core.config_loader.API_KEYS")
def test_defensive_breaches_success(mock_api_keys, mock_check_hibp):
    """Tests a successful 'defensive breaches' command."""
    # Simulate the presence of an API key

    mock_api_keys.hibp_api_key = "fake_key"
    # Simulate that the function returns a Pydantic model

    mock_check_hibp.return_value.model_dump.return_value = {"breaches": []}

    result = runner.invoke(app, ["defensive", "breaches", "mycompany.com"])
    assert result.exit_code == 0
    assert "Starting HIBP breach check for mycompany.com" in result.stdout


def test_defensive_breaches_no_api_key():
    """Tests 'defensive breaches' without an API key."""
    # Here we don't mock the API key, so it will be None
    # The test should pass because the function will simply not execute the core logic

    result = runner.invoke(app, ["defensive", "breaches", "mycompany.com"])
    assert result.exit_code == 0
    # Check that there is no output, as the key check stops execution

    assert "Successfully saved" not in result.stdout
