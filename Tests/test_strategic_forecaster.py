import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from chimera_intel.core.strategic_forecaster import forecaster_app, StrategicForecaster
import datetime

# Since the schemas are in other modules, we'll create simple mock objects
# for them to use as return values in our tests. This avoids complex imports.


def create_mock_insider_trading_result(transactions, error=None):
    mock_result = MagicMock()
    mock_result.transactions = transactions
    mock_result.error = error
    return mock_result


def create_mock_transaction(date, value):
    mock_tx = MagicMock()
    mock_tx.model_dump.return_value = {
        "transactionDate": date,
        "value": value,
    }
    return mock_tx


def create_mock_twitter_result(tweets, error=None):
    mock_result = MagicMock()
    mock_result.tweets = tweets
    mock_result.error = error
    return mock_result


def create_mock_tweet(timestamp):
    mock_tweet = MagicMock()
    mock_tweet.model_dump.return_value = {"created_at": timestamp}
    return mock_tweet


runner = CliRunner()


@pytest.fixture
def mock_dependencies():
    """A single fixture to mock all external calls."""
    with patch(
        "chimera_intel.core.strategic_forecaster.get_insider_transactions"
    ) as mock_finint, patch(
        "chimera_intel.core.strategic_forecaster.track_narrative"
    ) as mock_narrative, patch(
        "chimera_intel.core.strategic_forecaster.monitor_twitter_stream"
    ) as mock_social, patch(
        "chimera_intel.core.strategic_forecaster.save_forecast_to_db"
    ) as mock_db:

        # Set up return values for each mock

        mock_finint.return_value = create_mock_insider_trading_result(
            transactions=[create_mock_transaction(datetime.date(2023, 10, 1), 10000)]
        )
        mock_narrative.return_value = [
            {"sentiment": "positive", "content": "Good news"}
        ]
        mock_social.return_value = create_mock_twitter_result(
            tweets=[create_mock_tweet(datetime.datetime.now())]
        )

        yield {
            "finint": mock_finint,
            "narrative": mock_narrative,
            "social": mock_social,
            "db": mock_db,
        }


def test_run_forecast_command(mock_dependencies):
    """Tests the CLI command with mocked dependencies."""
    result = runner.invoke(
        forecaster_app,
        [
            "run",
            "Test the command",
            "--ticker",
            "TEST",
            "--narrative",
            "testing",
            "--keywords",
            "test,mock",
        ],
    )
    assert result.exit_code == 0
    assert "Running AI-driven scenario model" in result.stdout
    assert "Loaded 1 insider transactions for TEST" in result.stdout
    assert "Analyzed narrative for 'testing'" in result.stdout
    assert "Monitored 1 tweets" in result.stdout


def test_forecaster_initialization_with_data(mock_dependencies):
    """Tests that the forecaster loads data from modules correctly."""
    forecaster = StrategicForecaster(
        ticker="TEST", narrative_query="testing", twitter_keywords=["test", "mock"]
    )
    assert not forecaster.data_streams.empty
    assert "insider_trading_volume" in forecaster.data_streams.columns


def test_forecaster_fallback_to_dummy_data():
    """Tests that the forecaster uses dummy data when no inputs are given."""
    # We patch the dependencies to ensure they are not called

    with patch(
        "chimera_intel.core.strategic_forecaster.get_insider_transactions"
    ), patch("chimera_intel.core.strategic_forecaster.track_narrative"), patch(
        "chimera_intel.core.strategic_forecaster.monitor_twitter_stream"
    ):

        forecaster = StrategicForecaster()

        # To capture print output, we would need to patch 'console.print'
        # For simplicity, we'll just check the resulting data

        assert forecaster.data_streams.empty


def test_scenario_modeling_saves_to_db(mock_dependencies):
    """Tests that the scenario modeling saves the result to the database."""
    forecaster = StrategicForecaster()
    forecaster.run_scenario_model("A test scenario")
    mock_dependencies["db"].assert_called_once()

    # Check that the scenario passed to the db function is correct

    call_args, _ = mock_dependencies["db"].call_args
    assert call_args[0] == "A test scenario"
