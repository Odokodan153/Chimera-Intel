import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from chimera_intel.core.autonomous import autonomous_app

runner = CliRunner()


@pytest.fixture
def mock_db_connection(mocker):
    """Mocks the psycopg2 database connection and cursor."""
    mock_cursor = MagicMock()
    # Simulate the raw tuple format returned by cursor.fetchall()

    mock_cursor.fetchall.return_value = [
        (
            "Competitor X will launch a new product.",
            False,
            "Competitor X did not launch a new product; they acquired a startup instead.",
        )
    ]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    # Patch the correct function: get_db_connection

    mocker.patch(
        "chimera_intel.core.autonomous.get_db_connection", return_value=mock_conn
    )


@pytest.fixture
def mock_db_connection_no_data(mocker):
    """Mocks the database connection to return no data."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []  # Empty list to simulate no records
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mocker.patch(
        "chimera_intel.core.autonomous.get_db_connection", return_value=mock_conn
    )


@patch("chimera_intel.core.autonomous.generate_swot_from_data")
@patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_api_key")
def test_optimize_models_success(mock_ai_task, mock_db_connection):
    """
    Tests the successful run of the optimize-models command.
    """
    # --- Setup Mocks ---
    # No need to mock mock_api_keys.google_api_key here anymore

    # Mock the return object from the AI function to have the .analysis_text attribute
    ai_return_object = MagicMock()
    ai_return_object.analysis_text = "Recommendation: The model failed to predict an acquisition. Suggestion: Incorporate M&A data from FININT."
    ai_return_object.error = None
    mock_ai_task.return_value = ai_return_object

    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )

    assert result.exit_code == 0
    assert "Model Optimization Plan" in result.stdout
    assert "Incorporate M&A data" in result.stdout
    mock_ai_task.assert_called_once()
    prompt_arg = mock_ai_task.call_args[0][0]
    assert "You are a Machine Learning Operations (MLOps) specialist" in prompt_arg
    assert "Prediction Correct: False" in prompt_arg
    assert "acquired a startup instead" in prompt_arg


@patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_api_key")
def test_optimize_models_no_data(mock_db_connection_no_data):
    """
    Tests the command's behavior when no performance data is found.
    """
    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )

    # Typer.Exit() without a code defaults to exit_code=1
    assert result.exit_code == 1
    assert "No performance records found" in result.stdout