import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested

from chimera_intel.core.strategic_forecaster import forecaster_app
from chimera_intel.core.ai_core import AIResult

# Create a CliRunner for invoking the app in tests

runner = CliRunner()


@pytest.fixture
def mock_db_connection(mocker):
    """
    A pytest fixture to mock the database connection and return aggregated data.
    """
    # This function is now directly patched, so this fixture is for clarity
    # and can be expanded if more complex DB interactions are needed.

    pass


@pytest.fixture
def mock_ai_task(mocker):
    """A pytest fixture to mock the AI-powered generation task."""
    # Mock the AIResult object that the application expects

    mock_result = AIResult(
        analysis_text="Forecast: Competitor will likely announce a new partnership.",
        error=None,
    )
    return mocker.patch(
        "chimera_intel.core.strategic_forecaster.generate_swot_from_data",
        return_value=mock_result,
    )


@patch("chimera_intel.core.strategic_forecaster.get_aggregated_data_for_target")
def test_run_forecast_command_success(mock_get_data, mock_ai_task, mocker):
    """
    Tests a successful run of the forecast command.
    """
    # --- Arrange ---
    # Mock the API key to pass the configuration check

    mocker.patch(
        "chimera_intel.core.strategic_forecaster.API_KEYS.google_api_key", "fake_key"
    )
    # Mock the data returned from the database for the target

    mock_get_data.return_value = {
        "financials": {"marketCap": 1000000},
        "news": ["Recent positive press release"],
    }

    # --- Act ---
    # Invoke the CLI command correctly.
    # The command is just the app itself with the target and topic arguments.

    result = runner.invoke(
        forecaster_app, ["--target", "TestCorp", "--topic", "Market Expansion"]
    )

    # --- Assert ---

    assert result.exit_code == 0
    # Check for the initial status message

    assert "Generating strategic forecast for TestCorp" in result.stdout
    # Check that the AI-generated forecast is present in the output

    assert "Strategic Forecast" in result.stdout
    assert "Competitor will likely announce a new partnership" in result.stdout
    # Verify that the AI prompt was constructed correctly

    mock_ai_task.assert_called_once()
    prompt_arg = mock_ai_task.call_args[0][0]
    assert "You are a strategic forecaster" in prompt_arg
    assert "topic of Market Expansion" in prompt_arg
    assert '"marketCap": 1000000' in prompt_arg


@patch("chimera_intel.core.strategic_forecaster.get_aggregated_data_for_target")
def test_run_forecast_no_data(mock_get_data, mocker):
    """
    Tests that the command fails gracefully when no data is found for the target.
    """
    # --- Arrange ---

    mocker.patch(
        "chimera_intel.core.strategic_forecaster.API_KEYS.google_api_key", "fake_key"
    )
    # Simulate that no data was found in the database

    mock_get_data.return_value = None

    # --- Act ---

    result = runner.invoke(
        forecaster_app, ["--target", "EmptyCorp", "--topic", "Anything"]
    )

    # --- Assert ---
    # The application should exit with a non-zero code when no data is found

    assert result.exit_code == 1
    assert "Error: No aggregated data found for target 'EmptyCorp'" in result.stdout
