import pytest
from typer.testing import CliRunner
import psycopg2
import requests
import pandas as pd
from unittest.mock import patch, MagicMock, mock_open, ANY
from chimera_intel.core.autonomous import autonomous_app, trigger_retraining_pipeline

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

# Fixture for CliRunner
@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_db_connection(mocker):
    """Mocks the psycopg2 database connection and cursor with forecast data."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [
        (
            "Competitor X will launch a new product.",
            False,
            "Competitor X did not launch a new product; they acquired a startup instead.",
        ),
        (
            "Market Y will grow by 10%.",
            True,
            "Market Y grew by 11%.",
        ),
    ]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mocker.patch(
        "chimera_intel.core.autonomous.get_db_connection", return_value=mock_conn
    )
    return mock_conn, mock_cursor


@pytest.fixture
def mock_db_connection_no_data(mocker):
    """Mocks the database connection to return no data."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []  # Empty list
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mocker.patch(
        "chimera_intel.core.autonomous.get_db_connection", return_value=mock_conn
    )
    return mock_conn, mock_cursor


@pytest.fixture
def mock_db_connection_ab_test(mocker):
    """Mocks the database connection with A/B test results."""
    mock_cursor = MagicMock()
    # (model_variant, accuracy, latency)
    mock_cursor.fetchall.return_value = [
        ("variant_A", 0.85, 120.5),
        ("variant_B", 0.92, 150.0), # Winner
        ("variant_C", 0.90, 110.0),
    ]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mocker.patch(
        "chimera_intel.core.autonomous.get_db_connection", return_value=mock_conn
    )
    return mock_conn, mock_cursor

@pytest.fixture
def mock_db_connection_backtest(mocker):
    """Mocks the database connection with historical forecast data."""
    mock_cursor = MagicMock()
    # (scenario, predicted_outcome, actual_outcome)
    mock_cursor.fetchall.return_value = [
        ("Scenario 1", "A", "A"),
        ("Scenario 2", "B", "C"),
        ("Scenario 3", "A", "A"),
        ("Scenario 4", "C", "C"),
    ]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mocker.patch(
        "chimera_intel.core.autonomous.get_db_connection", return_value=mock_conn
    )
    return mock_conn, mock_cursor

@pytest.fixture
def mock_db_connection_error(mocker):
    """Mocks the database connection to raise a psycopg2 Error."""
    mocker.patch(
        "chimera_intel.core.autonomous.get_db_connection",
        side_effect=psycopg2.Error("Test DB Error"),
    )

@pytest.fixture
def mock_api_keys(mocker):
    """Mocks all required API_KEYS attributes."""
    mock_keys = MagicMock()
    mock_keys.google_api_key = "fake_google_key"
    mock_keys.cicd_webhook_url = "https://fake.webhook/trigger"
    mock_keys.cicd_auth_token = "fake_auth_token"
    mocker.patch("chimera_intel.core.autonomous.API_KEYS", mock_keys)
    return mock_keys

@pytest.fixture
def mock_ai_task(mocker):
    """Mocks the generate_swot_from_data function."""
    ai_return_object = MagicMock()
    ai_return_object.analysis_text = "Recommendation: Incorporate M&A data."
    ai_return_object.error = None
    return mocker.patch(
        "chimera_intel.core.autonomous.generate_swot_from_data",
        return_value=ai_return_object,
    )

@pytest.fixture
def mock_ai_task_error(mocker):
    """Mocks the generate_swot_from_data function to return an error."""
    ai_return_object = MagicMock()
    ai_return_object.analysis_text = None
    ai_return_object.error = "AI processing failed"
    return mocker.patch(
        "chimera_intel.core.autonomous.generate_swot_from_data",
        return_value=ai_return_object,
    )

# --- Tests for trigger_retraining_pipeline ---

@patch("chimera_intel.core.autonomous.requests.post")
def test_trigger_retraining_pipeline_success(mock_post, mock_api_keys, capsys):
    """Tests successful triggering of the retraining pipeline with auth."""
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    trigger_retraining_pipeline("Test Plan", "Test Reason")

    captured = capsys.readouterr()
    assert "Triggering automated model retraining pipeline" in captured.out
    assert "Successfully triggered retraining pipeline" in captured.out
    
    mock_post.assert_called_once_with(
        "https://fake.webhook/trigger",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer fake_auth_token",
        },
        json={
            "event_type": "chimera_retraining_trigger",
            "client_payload": {"reason": "Test Reason", "optimization_plan": "Test Plan"},
        },
        timeout=30,
    )

@patch("chimera_intel.core.autonomous.requests.post")
def test_trigger_retraining_pipeline_no_auth(mock_post, mock_api_keys, capsys):
    """Tests successful triggering when no auth token is provided."""
    mock_api_keys.cicd_auth_token = None # No auth token
    
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    trigger_retraining_pipeline("Test Plan", "Test Reason")
    
    mock_post.assert_called_once_with(
        "https://fake.webhook/trigger",
        headers={"Content-Type": "application/json"}, # No Authorization header
        json=ANY,
        timeout=30,
    )

def test_trigger_retraining_pipeline_no_webhook(mock_api_keys, capsys):
    """Tests failure when CICD_WEBHOOK_URL is not set."""
    mock_api_keys.cicd_webhook_url = None # No webhook URL

    trigger_retraining_pipeline("Test Plan", "Test Reason")
    
    captured = capsys.readouterr()
    assert "Error:" in captured.out
    assert "CICD_WEBHOOK_URL is not set" in captured.out

@patch("chimera_intel.core.autonomous.requests.post", side_effect=requests.exceptions.RequestException("Test Request Error"))
@patch("builtins.open", new_callable=mock_open)
def test_trigger_retraining_pipeline_request_exception(mock_file_open, mock_post, mock_api_keys, capsys):
    """Tests the fallback behavior when a requests exception occurs."""
    trigger_retraining_pipeline("Test Plan", "Test Reason")
    
    captured = capsys.readouterr()
    assert "Error triggering retraining pipeline" in captured.out
    assert "Test Request Error" in captured.out
    assert "Optimization plan saved to model_optimization_plan_failed.txt" in captured.out
    
    # Check that the fallback file was written to
    mock_file_open.assert_called_once_with("model_optimization_plan_failed.txt", "w")
    mock_file_open().write.assert_called_once_with("Test Plan")


# --- Tests for "optimize-models" CLI command ---

def test_optimize_models_success(runner, mock_db_connection, mock_api_keys, mock_ai_task):
    """Tests the successful run of the optimize-models command."""
    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )
    
    assert result.exit_code == 0
    assert "Model Optimization Plan" in result.stdout
    assert "Incorporate M&A data" in result.stdout
    assert "Note:" in result.stdout # Should show note about --auto-trigger
    
    mock_ai_task.assert_called_once()
    prompt_arg = mock_ai_task.call_args[0][0]
    assert "You are a Machine Learning Operations (MLOps) specialist" in prompt_arg
    assert "Prediction Correct: False" in prompt_arg
    assert "acquired a startup instead" in prompt_arg
    assert "Prediction Correct: True" in prompt_arg # Check both records are in prompt
    assert "Market Y grew by 11%" in prompt_arg

@patch("chimera_intel.core.autonomous.trigger_retraining_pipeline")
def test_optimize_models_auto_trigger(mock_trigger, runner, mock_db_connection, mock_api_keys, mock_ai_task):
    """Tests the --auto-trigger flag."""
    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster", "--auto-trigger"],
    )
    
    assert result.exit_code == 0
    assert "Model Optimization Plan" in result.stdout
    assert "Incorporate M&A data" in result.stdout
    assert "Note:" not in result.stdout # Should not show the note
    
    # Check that the trigger function was called
    mock_trigger.assert_called_once_with("Recommendation: Incorporate M&A data.")

def test_optimize_models_no_data(runner, mock_db_connection_no_data, mock_api_keys):
    """Tests the command's behavior when no performance data is found."""
    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )
    assert result.exit_code == 1
    assert "No performance records found" in result.stdout

def test_optimize_models_unsupported_module(runner, mock_api_keys):
    """Tests running with an unsupported module name."""
    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "unsupported_module"],
    )
    assert result.exit_code == 1
    assert "Only the 'forecaster' module is supported" in result.stdout

def test_optimize_models_no_ai_key(runner, mock_api_keys):
    """Tests failure when the AI API key is not set."""
    mock_api_keys.google_api_key = None # Unset the key
    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )
    assert result.exit_code == 1
    assert "GOOGLE_API_KEY is not set" in result.stdout

def test_optimize_models_ai_error(runner, mock_db_connection, mock_api_keys, mock_ai_task_error):
    """Tests failure when the AI function returns an error."""
    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )
    assert result.exit_code == 1
    assert "AI Error:" in result.stdout
    assert "AI processing failed" in result.stdout

def test_optimize_models_db_error(runner, mock_db_connection_error, mock_api_keys):
    """Tests failure when the database connection fails."""
    result = runner.invoke(
        autonomous_app,
        ["optimize-models", "--module", "forecaster"],
    )
    assert result.exit_code == 1
    assert "Database Error:" in result.stdout
    assert "Test DB Error" in result.stdout

# --- Tests for "analyze-ab-test" CLI command ---

def test_analyze_ab_test_success(runner, mock_db_connection_ab_test):
    """Tests successful A/B test analysis."""
    result = runner.invoke(autonomous_app, ["analyze-ab-test"])
    
    assert result.exit_code == 0
    assert "Winning Model Variant: variant_B" in result.stdout
    assert "Accuracy: 0.9200" in result.stdout
    assert "Latency: 150.0000 ms" in result.stdout
    assert "Note:" in result.stdout # Note about --auto-deploy

def test_analyze_ab_test_auto_deploy(runner, mock_db_connection_ab_test):
    """Tests A/B test analysis with --auto-deploy flag."""
    result = runner.invoke(autonomous_app, ["analyze-ab-test", "--auto-deploy"])
    
    assert result.exit_code == 0
    assert "Winning Model Variant: variant_B" in result.stdout
    assert "Automatically deploying winning variant 'variant_B'" in result.stdout
    assert "Deployment triggered successfully (simulated)" in result.stdout
    assert "Note:" not in result.stdout

def test_analyze_ab_test_no_data(runner, mock_db_connection_no_data):
    """Tests A/B test analysis when no data is found."""
    result = runner.invoke(autonomous_app, ["analyze-ab-test"])
    assert result.exit_code == 1
    assert "No A/B test results found" in result.stdout

def test_analyze_ab_test_db_error(runner, mock_db_connection_error):
    """Tests A/B test analysis with a database error."""
    result = runner.invoke(autonomous_app, ["analyze-ab-test"])
    assert result.exit_code == 1
    assert "Database Error:" in result.stdout
    assert "Test DB Error" in result.stdout

# --- Tests for "detect-drift" CLI command ---

@patch("chimera_intel.core.autonomous.pd.read_csv")
@patch("chimera_intel.core.autonomous.ks_2samp")
def test_detect_drift_detected(mock_ks_2samp, mock_read_csv, runner):
    """Tests drift detection when drift is found."""
    mock_df = pd.DataFrame({"feature1": [1, 2, 3], "feature2": [4, 5, 6]})
    mock_read_csv.return_value = mock_df
    
    # Mock p-value < 0.05 (drift) for feature1
    # Mock p-value > 0.05 (no drift) for feature2
    mock_ks_2samp.side_effect = [
        (0.5, 0.01), # (statistic, p-value) for feature1
        (0.1, 0.7),  # (statistic, p-value) for feature2
    ]
    
    result = runner.invoke(autonomous_app, ["detect-drift"], input="baseline.csv\nnew.csv\n")
    
    assert result.exit_code == 0
    assert "Drift detected in column 'feature1'" in result.stdout
    assert "No significant data drift detected" not in result.stdout

@patch("chimera_intel.core.autonomous.pd.read_csv")
@patch("chimera_intel.core.autonomous.ks_2samp")
def test_detect_drift_no_drift(mock_ks_2samp, mock_read_csv, runner):
    """Tests drift detection when no drift is found."""
    mock_df = pd.DataFrame({"feature1": [1, 2, 3]})
    mock_read_csv.return_value = mock_df
    
    mock_ks_2samp.return_value = (0.1, 0.7) # No drift
    
    result = runner.invoke(autonomous_app, ["detect-drift"], input="baseline.csv\nnew.csv\n")
    
    assert result.exit_code == 0
    assert "No significant data drift detected" in result.stdout
    assert "Drift detected" not in result.stdout

@patch("chimera_intel.core.autonomous.pd.read_csv")
@patch("chimera_intel.core.autonomous.ks_2samp")
@patch("chimera_intel.core.autonomous.trigger_retraining_pipeline")
def test_detect_drift_auto_trigger(mock_trigger, mock_ks_2samp, mock_read_csv, runner, mock_api_keys):
    """Tests drift detection with --auto-trigger."""
    mock_df = pd.DataFrame({"feature1": [1, 2, 3]})
    mock_read_csv.return_value = mock_df
    
    mock_ks_2samp.return_value = (0.5, 0.01) # Drift
    
    result = runner.invoke(autonomous_app, ["detect-drift", "--auto-trigger"], input="baseline.csv\nnew.csv\n")
    
    assert result.exit_code == 0
    assert "Drift detected" in result.stdout
    mock_trigger.assert_called_once_with(
        "Data drift detected in one or more features.", reason="Data Drift"
    )

@patch("chimera_intel.core.autonomous.pd.read_csv", side_effect=FileNotFoundError("File not found: baseline.csv"))
def test_detect_drift_file_not_found(mock_read_csv, runner):
    """Tests drift detection with a FileNotFoundError."""
    result = runner.invoke(autonomous_app, ["detect-drift"], input="baseline.csv\nnew.csv\n")
    
    assert result.exit_code == 1
    assert "Error:" in result.stdout
    assert "File not found: baseline.csv" in result.stdout

@patch("chimera_intel.core.autonomous.pd.read_csv", side_effect=Exception("General CSV error"))
def test_detect_drift_general_error(mock_read_csv, runner):
    """Tests drift detection with a general exception."""
    result = runner.invoke(autonomous_app, ["detect-drift"], input="baseline.csv\nnew.csv\n")
    
    assert result.exit_code == 1
    assert "An error occurred during drift detection" in result.stdout
    assert "General CSV error" in result.stdout

# --- Tests for "backtest" CLI command ---

def test_backtest_success(runner, mock_db_connection_backtest):
    """Tests successful backtesting."""
    result = runner.invoke(autonomous_app, ["backtest"], input="test_model\n")
    
    assert result.exit_code == 0
    assert "Backtesting Complete" in result.stdout
    assert "Total Forecasts: 4" in result.stdout
    assert "Correct Predictions: 3" in result.stdout
    assert "Accuracy: 75.00%" in result.stdout

def test_backtest_no_data(runner, mock_db_connection_no_data):
    """Tests backtesting when no historical data is found."""
    result = runner.invoke(autonomous_app, ["backtest"], input="test_model\n")
    
    assert result.exit_code == 1
    assert "No historical forecast data found for backtesting" in result.stdout

def test_backtest_db_error(runner, mock_db_connection_error):
    """Tests backtesting with a database error."""
    result = runner.invoke(autonomous_app, ["backtest"], input="test_model\n")
    
    assert result.exit_code == 1
    assert "Database Error:" in result.stdout
    assert "Test DB Error" in result.stdout