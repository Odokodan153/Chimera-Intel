import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# Import the application instance and the SWOTAnalysisResult schema

from chimera_intel.core.strategic_forecaster import strategic_forecaster_app
from chimera_intel.core.schemas import SWOTAnalysisResult

runner = CliRunner()


@patch("chimera_intel.core.strategic_forecaster.get_aggregated_data_for_target")
@patch("chimera_intel.core.strategic_forecaster.generate_swot_from_data")
@patch("chimera_intel.core.strategic_forecaster.API_KEYS")
def test_forecast_success(mock_api_keys, mock_generate_swot, mock_get_data):
    """
    Tests the successful run of a strategic forecast.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = {"market_trends": ["AI adoption"]}
    mock_generate_swot.return_value = SWOTAnalysisResult(
        analysis_text="Future trend: Increased focus on AI-driven security.",
        error=None,
    )

    # --- Run Command ---

    result = runner.invoke(strategic_forecaster_app, ["forecast", "TestCorp"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Forecasting strategic landscape for TestCorp..." in result.stdout
    assert "Strategic Forecast for TestCorp" in result.stdout
    assert "Future trend: Increased focus on AI-driven security." in result.stdout


@patch("chimera_intel.core.strategic_forecaster.get_aggregated_data_for_target")
@patch("chimera_intel.core.strategic_forecaster.API_KEYS")
def test_forecast_no_data(mock_api_keys, mock_get_data):
    """
    Tests the command's behavior when no aggregated data is found for the target.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "test_key"
    mock_get_data.return_value = None  # Simulate no data found

    # --- Run Command ---

    result = runner.invoke(strategic_forecaster_app, ["forecast", "nonexistent-target"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "No data found for target 'nonexistent-target'" in result.stdout


@patch("chimera_intel.core.strategic_forecaster.API_KEYS")
def test_forecast_no_api_key(mock_api_keys):
    """
    Tests that the command fails gracefully if the Google API key is not configured.
    """
    # --- Setup Mock ---

    mock_api_keys.google_api_key = None  # Simulate missing API key

    # --- Run Command ---

    result = runner.invoke(strategic_forecaster_app, ["forecast", "any-target"])

    # --- Assertions ---

    assert result.exit_code == 1
    assert "Error: Google API key not configured." in result.stdout
