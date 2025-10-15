import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# Import the application instance and the SWOTAnalysisResult schema

from chimera_intel.core.red_team import red_team_app
from chimera_intel.core.schemas import SWOTAnalysisResult

runner = CliRunner()


@patch("chimera_intel.core.red_team.get_aggregated_data_for_target")
@patch("chimera_intel.core.red_team.generate_swot_from_data")
@patch("chimera_intel.core.red_team.API_KEYS")
def test_generate_scenario_success(mock_api_keys, mock_generate_swot, mock_get_data):
    """
    Tests the successful generation of a red team scenario.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = {"vulnerabilities": ["CVE-2023-1234"]}
    mock_generate_swot.return_value = SWOTAnalysisResult(
        analysis_text="Scenario: Phishing campaign targeting employees.", error=None
    )

    # --- Run Command ---

    result = runner.invoke(red_team_app, ["generate", "TestCorp"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Generating Red Team scenario for TestCorp..." in result.stdout
    assert "Red Team Scenario for TestCorp" in result.stdout
    assert "Scenario: Phishing campaign targeting employees." in result.stdout


@patch("chimera_intel.core.red_team.get_aggregated_data_for_target")
@patch("chimera_intel.core.red_team.API_KEYS")
def test_generate_scenario_no_data(mock_api_keys, mock_get_data):
    """
    Tests the command's behavior when no aggregated data is found for the target.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = None  # Simulate no data found

    # --- Run Command ---

    result = runner.invoke(red_team_app, ["generate", "nonexistent-target"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "No data found for target 'nonexistent-target'" in result.stdout


@patch("chimera_intel.core.red_team.API_KEYS")
def test_generate_scenario_no_api_key(mock_api_keys):
    """
    Tests that the command fails gracefully if the Google API key is not configured.
    """
    # --- Setup Mock ---

    mock_api_keys.google_api_key = None  # Simulate missing API key

    # --- Run Command ---

    result = runner.invoke(red_team_app, ["generate", "any-target"])

    # --- Assertions ---

    assert result.exit_code == 1
    assert "Error: Google API key not configured." in result.stdout
