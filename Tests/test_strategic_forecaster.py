import pytest
from typer.testing import CliRunner
from unittest.mock import patch
import pandas as pd

from chimera_intel.cli import app as main_app
from chimera_intel.core.strategic_forecaster import forecaster_app

from chimera_intel.core.schemas import (
    InsiderTransactionResult,
    InsiderTransaction,
    TwitterStreamResult,
    Tweet,
)

runner = CliRunner()

main_app.add_typer(forecaster_app, name="forecaster")


@pytest.fixture(autouse=True)
def mock_save_db(mocker):
    """Patch database writes."""
    mocker.patch("chimera_intel.core.strategic_forecaster.save_forecast_to_db")


@pytest.fixture
def mock_data_streams(mocker):
    """Patch FININT, narrative, and Twitter data."""
    mocker.patch(
        "chimera_intel.core.strategic_forecaster.get_insider_transactions",
        return_value=InsiderTransactionResult(
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
        ),
    )
    mocker.patch(
        "chimera_intel.core.strategic_forecaster.track_narrative",
        return_value=[{"sentiment": "positive"}, {"sentiment": "negative"}],
    )
    mocker.patch(
        "chimera_intel.core.strategic_forecaster.monitor_twitter_stream",
        return_value=TwitterStreamResult(
            query="AI,finance",
            tweets=[
                Tweet(
                    id="123",
                    text="Test tweet",
                    author_id="456",
                    created_at="2023-01-01T12:00:00Z",
                )
            ],
        ),
    )


def test_run_forecast_success(mocker, mock_data_streams):
    """Test the 'run' command with all data streams."""
    mock_console_print = mocker.patch(
        "chimera_intel.core.strategic_forecaster.console.print"
    )

    result = runner.invoke(
        main_app,
        [
            "forecaster",
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
    assert result.exit_code == 0, result.output
    mock_console_print.assert_any_call(
        "[bold cyan]Loading real-time data streams...[/bold cyan]"
    )
    mock_console_print.assert_any_call(
        "[bold cyan]Running AI-driven scenario model for: 'Market expansion into AI'[/bold cyan]"
    )
    mock_console_print.assert_any_call(
        "[bold cyan]Detecting anomalies and weak signals...[/bold cyan]"
    )
    mock_console_print.assert_any_call(
        "[bold cyan]Analyzing trends and trajectories...[/bold cyan]"
    )


def test_run_forecast_no_data(mocker):
    """Test the 'run' command with no data loaded."""
    mock_console_print = mocker.patch(
        "chimera_intel.core.strategic_forecaster.console.print"
    )
    result = runner.invoke(main_app, ["forecaster", "run", "A scenario with no data"])

    assert result.exit_code == 0, result.output
    mock_console_print.assert_any_call(
        "[bold yellow]Warning:[/bold yellow] No data loaded. Forecasting will be limited."
    )


@patch("chimera_intel.core.strategic_forecaster.StrategicForecaster._load_real_data")
def test_forecast_insufficient_data_for_trends(mock_load_data, mocker):
    """Test when loaded data is insufficient for ARIMA trend analysis."""
    mock_console_print = mocker.patch(
        "chimera_intel.core.strategic_forecaster.console.print"
    )
    mock_load_data.return_value = pd.DataFrame({"insider_trading_volume": [1, 2, 3]})

    result = runner.invoke(main_app, ["forecaster", "run", "test-scenario"])

    assert result.exit_code == 0, result.output
    mock_console_print.assert_any_call(
        "  - [yellow]Not enough data to generate forecast for insider_trading_volume.[/yellow]"
    )
