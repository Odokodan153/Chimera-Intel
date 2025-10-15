import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested

from chimera_intel.core.red_team import red_team_app
from chimera_intel.core.ai_core import AIResult

runner = CliRunner()


@patch("chimera_intel.core.red_team.get_aggregated_data_for_target")
@patch("chimera_intel.core.red_team.generate_swot_from_data")
@patch("chimera_intel.core.red_team.API_KEYS")
def test_run_red_team_analysis_success(
    mock_api_keys, mock_generate_swot, mock_get_data
):
    """
    Tests the successful run of a Red Team analysis.
    """
    # --- Setup Mocks ---
    # 1. Mock the API key to ensure the check passes.

    mock_api_keys.google_api_key = "test_key"

    # 2. Mock the aggregated data returned from the database.

    mock_get_data.return_value = {
        "domains": ["corp.com"],
        "employees": ["j.doe@corp.com"],
    }

    # 3. Mock the AI analysis result.

    mock_ai_result = AIResult(
        analysis_text="Attack Vector 1: Phishing campaign targeting j.doe@corp.com.",
        error=None,
    )
    mock_generate_swot.return_value = mock_ai_result

    # --- Run Command ---

    result = runner.invoke(red_team_app, ["generate", "corp.com"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Generating potential attack vectors for corp.com..." in result.stdout
    assert "Red Team Analysis for corp.com:" in result.stdout
    assert "Attack Vector 1: Phishing campaign" in result.stdout

    # Verify the AI prompt was generated correctly

    mock_generate_swot.assert_called_once()
    prompt_arg = mock_generate_swot.call_args[0][0]
    assert (
        "As a red team operator, analyze the following aggregated OSINT data"
        in prompt_arg
    )
    assert "'employees': ['j.doe@corp.com']" in prompt_arg


@patch("chimera_intel.core.red_team.get_aggregated_data_for_target")
@patch("chimera_intel.core.red_team.API_KEYS")
def test_run_red_team_analysis_no_data(mock_api_keys, mock_get_data):
    """
    Tests the command's behavior when no aggregated data is found for the target.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = None  # Simulate no data found

    # --- Run Command ---

    result = runner.invoke(red_team_app, ["generate", "nonexistent-target"])

    # --- Assertions ---
    # The command should still exit cleanly but not produce a report.
    # The message about no data is handled within the get_aggregated_data_for_target
    # function, which is mocked here. So we just check that no analysis is printed.

    assert result.exit_code == 0
    assert "Red Team Analysis for nonexistent-target:" not in result.stdout


@patch("chimera_intel.core.red_team.API_KEYS")
def test_run_red_team_analysis_no_api_key(mock_api_keys):
    """
    Tests that the command fails gracefully if the Google API key is not configured.
    """
    # --- Setup Mock ---

    mock_api_keys.google_api_key = None  # Simulate missing API key

    # --- Run Command ---

    result = runner.invoke(red_team_app, ["generate", "corp.com"])

    # --- Assertions ---

    assert (
        result.exit_code == 0
    )  # The CLI command itself doesn't exit with an error code
    assert "Error:" in result.stdout
    assert "Google API key not configured." in result.stdout
