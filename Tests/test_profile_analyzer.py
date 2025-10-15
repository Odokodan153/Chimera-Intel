from typer.testing import CliRunner
from unittest.mock import patch

# Import the application instance and the SWOTAnalysisResult schema

from chimera_intel.core.profile_analyzer import profile_analyzer_app
from chimera_intel.core.schemas import SWOTAnalysisResult

runner = CliRunner()


@patch("chimera_intel.core.profile_analyzer.get_aggregated_data_for_target")
@patch("chimera_intel.core.profile_analyzer.generate_swot_from_data")
@patch("chimera_intel.core.profile_analyzer.API_KEYS")
def test_analyze_profile_success(mock_api_keys, mock_generate_swot, mock_get_data):
    """
    Tests the successful run of a profile analysis.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = {"key_personnel": ["John Doe"]}
    mock_generate_swot.return_value = SWOTAnalysisResult(
        analysis_text="Strengths: Experienced leadership.", error=None
    )

    # --- Run Command ---

    result = runner.invoke(profile_analyzer_app, ["analyze", "TestCorp"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Analyzing profile for TestCorp..." in result.stdout
    assert "Threat Profile Analysis for TestCorp" in result.stdout
    assert "Strengths: Experienced leadership." in result.stdout


@patch("chimera_intel.core.profile_analyzer.get_aggregated_data_for_target")
@patch("chimera_intel.core.profile_analyzer.API_KEYS")
def test_analyze_profile_no_data(mock_api_keys, mock_get_data):
    """
    Tests the command's behavior when no aggregated data is found for the target.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = None  # Simulate no data found

    # --- Run Command ---

    result = runner.invoke(profile_analyzer_app, ["analyze", "nonexistent-target"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "No data found for target 'nonexistent-target'" in result.stdout


@patch("chimera_intel.core.profile_analyzer.API_KEYS")
def test_analyze_profile_no_api_key(mock_api_keys):
    """
    Tests that the command fails gracefully if the Google API key is not configured.
    """
    # --- Setup Mock ---

    mock_api_keys.google_api_key = None  # Simulate missing API key

    # --- Run Command ---

    result = runner.invoke(profile_analyzer_app, ["analyze", "any-target"])

    # --- Assertions ---

    assert result.exit_code == 1
    assert "Error: Google API key not configured." in result.stdout
