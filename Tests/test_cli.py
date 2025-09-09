"""
Tests for the main Command-Line Interface (CLI) of the Chimera Intel application.

This test suite uses Typer's CliRunner to simulate command-line inputs and verify
that the application behaves as expected, including correct command routing,
parameter validation, and output.
"""

import subprocess
import sys
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock, MagicMock
from chimera_intel.cli import app

# Create a runner instance to invoke commands


runner = CliRunner()

# --- Tests for basic app functionality ---


def test_main_app_help():
    """Tests if the main --help command works and displays commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    # Check that the main command groups are listed in the help output

    assert "scan" in result.stdout
    assert "defensive" in result.stdout
    assert "analysis" in result.stdout
    assert "report" in result.stdout


# --- Test for main script entry ---


def test_main_script_entry():
    """
    Tests running the CLI script directly.
    """
    result = subprocess.run(
        [sys.executable, "-m", "chimera_intel.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Usage" in result.stdout


# --- Tests for the 'scan' command group ---

# The patch path must point to where the function is DEFINED.


@patch("chimera_intel.core.footprint.gather_footprint_data", new_callable=AsyncMock)
def test_scan_footprint_success(mock_gather_footprint: AsyncMock):
    """
    Tests a successful 'scan footprint run' command.

    Args:
        mock_gather_footprint (AsyncMock): A mock for the async data gathering function.
    """
    # 1. Create a mock object to simulate the Pydantic model (the result of await)

    mock_result_model = MagicMock()

    # 2. Configure its .model_dump() method to return the test data

    mock_result_model.model_dump.return_value = {
        "domain": "example.com",
        "footprint": {},
    }

    # 3. Set the AsyncMock to return this mock object upon execution

    mock_gather_footprint.return_value = mock_result_model

    # The command path must match the structure in cli.py: scan -> footprint -> run

    result = runner.invoke(app, ["scan", "footprint", "run", "example.com"])

    assert result.exit_code == 0
    # Assert that the JSON output is present in the standard output

    assert '"domain": "example.com"' in result.stdout


def test_scan_footprint_invalid_domain():
    """Tests the 'scan footprint run' command with an invalid domain."""
    result = runner.invoke(app, ["scan", "footprint", "run", "invalid-domain"])
    # The command should exit with a non-zero code for an error

    assert result.exit_code == 1
    assert "is not a valid domain format" in result.stdout


# --- Tests for the 'defensive' command group ---


@patch("chimera_intel.core.defensive.check_hibp_breaches")
def test_defensive_breaches_success(mock_check_hibp: MagicMock):
    """
    Tests a successful 'defensive checks breaches' command.

    Args:
        mock_check_hibp (MagicMock): A mock for the HIBP check function.
    """
    # Simulate that the function returns a Pydantic model

    mock_check_hibp.return_value.model_dump.return_value = {"breaches": []}

    # Use a context manager to temporarily set the API key for this test

    with patch("chimera_intel.core.config_loader.API_KEYS.hibp_api_key", "fake_key"):
        # The command path must match the structure: defensive -> checks -> breaches

        result = runner.invoke(
            app, ["defensive", "checks", "breaches", "mycompany.com"]
        )
        assert result.exit_code == 0
        # Check for the JSON output, not the log message

        assert '"breaches": []' in result.stdout


@patch("chimera_intel.core.config_loader.API_KEYS.hibp_api_key", None)
def test_defensive_breaches_no_api_key():
    """
    Tests 'defensive checks breaches' when the API key is missing.

    Args:
        mock_api_key_none (MagicMock): A mock to ensure the API key is None.
    """
    # The command path must match the structure: defensive -> checks -> breaches

    result = runner.invoke(app, ["defensive", "checks", "breaches", "mycompany.com"])

    # The command should exit gracefully without an error

    assert result.exit_code == 0
    # It should not attempt to run the check, so this text should be missing

    assert "Starting HIBP breach check" not in result.stdout
