import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested

from chimera_intel.core.cultint import cultint_app
from chimera_intel.core.ai_core import AIResult

runner = CliRunner()


@patch("chimera_intel.core.cultint.get_aggregated_data_for_target")
@patch("chimera_intel.core.cultint.generate_swot_from_data")
@patch("chimera_intel.core.cultint.API_KEYS")
def test_analyze_target_success(mock_api_keys, mock_generate_swot, mock_get_data):
    """
    Tests the successful run of a CULTINT analysis.
    """
    # --- Setup Mocks ---
    # 1. Mock the API key to ensure the check passes.

    mock_api_keys.google_api_key = "test_key"

    # 2. Mock the aggregated data returned from the database.

    mock_get_data.return_value = {
        "key_personnel": ["John Doe"],
        "locations": ["Springfield"],
    }

    # 3. Mock the AI analysis result.

    mock_ai_result = AIResult(
        analysis_text="Analysis shows a hierarchical culture focused on tradition.",
        error=None,
    )
    mock_generate_swot.return_value = mock_ai_result

    # --- Run Command ---

    result = runner.invoke(cultint_app, ["analyze", "TestCorp"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Analyzing cultural landscape for TestCorp..." in result.stdout
    assert "Cultural Intelligence Analysis for TestCorp" in result.stdout
    assert "Analysis shows a hierarchical culture" in result.stdout

    # Verify the AI prompt was generated correctly

    mock_generate_swot.assert_called_once()
    prompt_arg = mock_generate_swot.call_args[0][0]
    assert (
        "As a cultural intelligence analyst, examine the following OSINT data"
        in prompt_arg
    )
    assert "TestCorp" in prompt_arg
    assert "'key_personnel': ['John Doe']" in prompt_arg


@patch("chimera_intel.core.cultint.get_aggregated_data_for_target")
@patch("chimera_intel.core.cultint.API_KEYS")
def test_analyze_target_no_data(mock_api_keys, mock_get_data):
    """
    Tests the command's behavior when no aggregated data is found for the target.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = None  # Simulate no data found

    # --- Run Command ---

    result = runner.invoke(cultint_app, ["analyze", "nonexistent-target"])

    # --- Assertions ---
    # The warning for no data is handled in the mocked function,
    # so we just check that the command exits cleanly without printing a report.

    assert result.exit_code == 0
    assert "Cultural Intelligence Analysis" not in result.stdout


@patch("chimera_intel.core.cultint.API_KEYS")
def test_analyze_target_no_api_key(mock_api_keys):
    """
    Tests that the command fails gracefully if the Google API key is not configured.
    """
    # --- Setup Mock ---

    mock_api_keys.google_api_key = None  # Simulate missing API key

    # --- Run Command ---

    result = runner.invoke(cultint_app, ["analyze", "any-target"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Error:" in result.stdout
    assert "Google API key not configured." in result.stdout
