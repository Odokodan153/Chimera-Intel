import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from chimera_intel.core.autonomous import autonomous_app
from chimera_intel.core.schemas import ForecastPerformance

runner = CliRunner()


@pytest.fixture
def mock_db_session(mocker):
    """Mocks the database session with sample forecast performance data."""
    mock_record = ForecastPerformance(
        scenario="Competitor X will launch a new product.",
        is_correct=False,
        outcome="Competitor X did not launch a new product; they acquired a startup instead.",
    )
    mock_query = MagicMock()
    mock_query.filter.return_value.all.return_value = [mock_record]
    mock_db = MagicMock()
    mock_db.query.return_value = mock_query
    return mocker.patch(
        "chimera_intel.core.autonomous.get_db", return_value=iter([mock_db])
    )


@patch("chimera_intel.core.autonomous.perform_generative_task")
def test_optimize_models_success(mock_ai_task, mock_db_session):
    """
    Tests the successful run of the optimize-models command.
    """
    mock_ai_task.return_value = "Recommendation: The model failed to predict an acquisition. Suggestion: Incorporate M&A data from FININT."

    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )

    assert result.exit_code == 0
    assert "Model Optimization Plan" in result.stdout
    assert "Incorporate M&A data" in result.stdout

    # Verify the AI was prompted correctly

    mock_ai_task.assert_called_once()
    prompt_arg = mock_ai_task.call_args[0][0]
    assert "You are a Machine Learning Operations (MLOps) specialist" in prompt_arg
    assert "Prediction Correct: False" in prompt_arg
    assert "acquired a startup instead" in prompt_arg


def test_optimize_models_no_data(mocker):
    """
    Tests the command's behavior when no performance data is found.
    """
    mock_query = MagicMock()
    mock_query.filter.return_value.all.return_value = []  # No data
    mock_db = MagicMock()
    mock_db.query.return_value = mock_query
    mocker.patch("chimera_intel.core.autonomous.get_db", return_value=iter([mock_db]))

    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )

    assert result.exit_code == 0
    assert "No performance records found" in result.stdout
