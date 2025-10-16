from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import pandas as pd

# Import the application instance

from chimera_intel.core.strategic_forecaster import forecaster_app
from chimera_intel.core.schemas import (
    InsiderTransaction,
    InsiderTransactionResult,
    TwitterStreamResult,
    Tweet,
)

runner = CliRunner()


@patch("chimera_intel.core.strategic_forecaster.save_forecast_to_db")
@patch("chimera_intel.core.strategic_forecaster.monitor_twitter_stream")
@patch("chimera_intel.core.strategic_forecaster.track_narrative")
@patch("chimera_intel.core.strategic_forecaster.get_insider_transactions")
def test_run_forecast_success(
    mock_get_insider, mock_track_narrative, mock_monitor_twitter, mock_save_db
):
    """
    Tests the successful execution of a forecast with all data streams.
    """
    # --- Setup Mocks ---
    # Mock FININT data

    mock_insider_result = InsiderTransactionResult(
        stock_symbol="TEST",
        transactions=[
            InsiderTransaction(
                companyName="Test Inc",
                insiderName="John Doe",
                transactionType="Buy",
                transactionDate="2023-01-01",
                transactionShares=100,
                transactionCode="P",
                price=10.0,
                change=100,
                value=1000,
            )
        ],
    )
    mock_get_insider.return_value = mock_insider_result

    # Mock Narrative data

    mock_track_narrative.return_value = [
        {"sentiment": "positive"},
        {"sentiment": "negative"},
    ]

    # Mock Social Media data

    mock_twitter_result = TwitterStreamResult(
        tweets=[
            Tweet(
                id="123",
                text="Test tweet",
                author_id="456",
                created_at="2023-01-01T12:00:00Z",
            )
        ]
    )
    mock_monitor_twitter.return_value = mock_twitter_result

    # --- Run Command ---

    result = runner.invoke(
        forecaster_app,
        [
            "run",
            "Market expansion into AI",
            "--ticker",
            "TEST",
            "--narrative",
            "AI in finance",
            "--keywords",
            "AI,finance",
        ],
    )

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Loading real-time data streams" in result.stdout
    assert "Running AI-driven scenario model" in result.stdout
    assert "Detecting anomalies" in result.stdout
    assert "Analyzing trends and trajectories" in result.stdout
    mock_save_db.assert_called_once()


def test_run_forecast_no_data():
    """
    Tests that the command handles cases where no data can be loaded.
    """
    # --- Run Command without mocks to simulate no data ---

    result = runner.invoke(forecaster_app, ["run", "A scenario with no data"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Warning: No data loaded. Forecasting will be limited." in result.stdout


@patch("chimera_intel.core.strategic_forecaster.StrategicForecaster._load_real_data")
def test_forecast_insufficient_data_for_trends(mock_load_data):
    """
    Tests the command's behavior when data is loaded, but it's not enough for trend analysis.
    """
    # --- Setup Mock ---
    # Return a DataFrame with too few rows for ARIMA model

    mock_load_data.return_value = pd.DataFrame({"insider_trading_volume": [1, 2, 3]})

    # --- Run Command ---

    result = runner.invoke(forecaster_app, ["run", "test-scenario"])

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Not enough data to generate forecast" in result.stdout
