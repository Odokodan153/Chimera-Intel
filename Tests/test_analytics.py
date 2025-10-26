import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
from typer.testing import CliRunner

# Import the functions and app to be tested
from src.chimera_intel.core.analytics import (
    get_negotiation_kpis,
    analytics_app,
)

# Runner for testing the Typer app
runner = CliRunner()


@pytest.fixture
def mock_db_params():
    """Fixture for valid database parameters."""
    return {
        "dbname": "testdb",
        "user": "testuser",
        "password": "testpass",
        "host": "localhost",
    }


@pytest.fixture
def mock_db_conn():
    """Fixture to mock the database connection and cursor."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    return mock_conn, mock_cursor


# --- Tests for get_negotiation_kpis ---


def test_get_kpis_missing_params():
    """Test KPI function when DB parameters are missing."""
    kpis = get_negotiation_kpis({"dbname": "test", "user": "user", "password": None})
    assert kpis == {"error": "Database connection parameters are missing."}


@patch("src.chimera_intel.core.analytics.psycopg2.connect")
def test_get_kpis_connection_error(mock_connect, mock_db_params):
    """Test KPI function when database connection fails."""
    mock_connect.return_value = None
    kpis = get_negotiation_kpis(mock_db_params)
    assert kpis == {"error": "Could not connect to the database."}


@patch("src.chimera_intel.core.analytics.psycopg2.connect")
def test_get_kpis_success(mock_connect, mock_db_params, mock_db_conn):
    """Test successful KPI calculation."""
    mock_conn, mock_cursor = mock_db_conn
    mock_connect.return_value = mock_conn

    # Mock the return values for the three SQL queries
    mock_cursor.fetchone.side_effect = [
        (80.0,),  # success_rate
        (1500.50,),  # avg_deal_value
        (8.5,),  # avg_length
    ]

    kpis = get_negotiation_kpis(mock_db_params)

    assert kpis == {
        "success_rate": 80.0,
        "average_deal_value": 1500.50,
        "average_negotiation_length": 8.5,
    }
    assert mock_cursor.execute.call_count == 3


@patch("src.chimera_intel.core.analytics.psycopg2.connect")
def test_get_kpis_success_no_data(mock_connect, mock_db_params, mock_db_conn):
    """Test successful KPI calculation when queries return None."""
    mock_conn, mock_cursor = mock_db_conn
    mock_connect.return_value = mock_conn

    # Mock queries returning None
    mock_cursor.fetchone.side_effect = [
        (None,),  # success_rate
        (None,),  # avg_deal_value
        (None,),  # avg_length
    ]

    kpis = get_negotiation_kpis(mock_db_params)

    assert kpis == {
        "success_rate": 0,
        "average_deal_value": 0,
        "average_negotiation_length": 0,
    }


@patch("src.chimera_intel.core.analytics.psycopg2.connect")
def test_get_kpis_db_exception(mock_connect, mock_db_params):
    """Test KPI function when a database exception occurs."""
    mock_connect.side_effect = Exception("Test DB Error")
    kpis = get_negotiation_kpis(mock_db_params)
    assert "error" in kpis
    assert "Test DB Error" in kpis["error"]


# --- Tests for plot_sentiment_trajectory (Typer command) ---


# FIX: Patch target changed to '.config_loader.API_KEYS'
@patch("src.chimera_intel.core.config_loader.API_KEYS", MagicMock())
@patch("src.chimera_intel.core.analytics.psycopg2.connect")
@patch("src.chimera_intel.core.analytics.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics.plt")
def test_plot_sentiment_missing_params(mock_plt, mock_read_sql, mock_connect):
    """Test plot command when DB parameters are missing from config."""
    # Simulate missing config values
    # FIX: Patch target changed to '.config_loader.API_KEYS'
    with patch("src.chimera_intel.core.config_loader.API_KEYS", MagicMock(db_name=None)):
        result = runner.invoke(analytics_app, ["plot-sentiment", "neg-123"])
        assert "Error: Database connection parameters are missing." in result.stdout


# FIX: Patch target changed to '.config_loader.API_KEYS'
@patch("src.chimera_intel.core.config_loader.API_KEYS", MagicMock())
@patch("src.chimera_intel.core.analytics.psycopg2.connect")
@patch("src.chimera_intel.core.analytics.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics.plt")
def test_plot_sentiment_connection_error(mock_plt, mock_read_sql, mock_connect):
    """Test plot command when DB connection fails."""
    mock_connect.return_value = None
    result = runner.invoke(analytics_app, ["plot-sentiment", "neg-123"])
    assert "Error: Could not connect to the database." in result.stdout


# FIX: Patch target changed to '.config_loader.API_KEYS'
@patch("src.chimera_intel.core.config_loader.API_KEYS", MagicMock())
@patch("src.chimera_intel.core.analytics.psycopg2.connect")
@patch("src.chimera_intel.core.analytics.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics.plt")
def test_plot_sentiment_no_messages(mock_plt, mock_read_sql, mock_connect, mock_db_conn):
    """Test plot command when no messages are found for the negotiation ID."""
    mock_connect.return_value = mock_db_conn[0]
    # Simulate empty DataFrame
    mock_read_sql.return_value = pd.DataFrame(columns=["timestamp", "sentiment"])

    result = runner.invoke(analytics_app, ["plot-sentiment", "neg-404"])
    assert "No messages found for negotiation ID: neg-404" in result.stdout


# FIX: Patch target changed to '.config_loader.API_KEYS'
@patch("src.chimera_intel.core.config_loader.API_KEYS", MagicMock())
@patch("src.chimera_intel.core.analytics.psycopg2.connect")
@patch("src.chimera_intel.core.analytics.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics.plt")
def test_plot_sentiment_save_to_file(
    mock_plt, mock_read_sql, mock_connect, mock_db_conn
):
    """Test plot command successfully saving plot to a file."""
    mock_connect.return_value = mock_db_conn[0]
    # Simulate valid DataFrame
    df = pd.DataFrame(
        {
            "timestamp": pd.to_datetime(["2023-01-01"]),
            "sentiment": [0.5],
        }
    )
    mock_read_sql.return_value = df

    result = runner.invoke(
        analytics_app, ["plot-sentiment", "neg-789", "--output", "test_plot.png"]
    )

    assert "Plot saved to test_plot.png" in result.stdout
    mock_plt.figure.assert_called_once()
    mock_plt.plot.assert_called_with(df["timestamp"], df["sentiment"], marker="o", linestyle="-")
    mock_plt.savefig.assert_called_with("test_plot.png")
    mock_plt.show.assert_not_called()


# FIX: Patch target changed to '.config_loader.API_KEYS'
@patch("src.chimera_intel.core.config_loader.API_KEYS", MagicMock())
@patch("src.chimera_intel.core.analytics.psycopg2.connect")
@patch("src.chimera_intel.core.analytics.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics.plt")
def test_plot_sentiment_show_plot(
    mock_plt, mock_read_sql, mock_connect, mock_db_conn
):
    """Test plot command successfully showing the plot (no output path)."""
    mock_connect.return_value = mock_db_conn[0]
    df = pd.DataFrame(
        {
            "timestamp": pd.to_datetime(["2023-01-01"]),
            "sentiment": [0.5],
        }
    )
    mock_read_sql.return_value = df

    runner.invoke(analytics_app, ["plot-sentiment", "neg-789"])

    mock_plt.savefig.assert_not_called()
    mock_plt.show.assert_called_once()


# FIX: Patch target changed to '.config_loader.API_KEYS'
@patch("src.chimera_intel.core.config_loader.API_KEYS", MagicMock())
@patch("src.chimera_intel.core.analytics.psycopg2.connect")
@patch("src.chimera_intel.core.analytics.pd.read_sql_query")
def test_plot_sentiment_db_exception(mock_read_sql, mock_connect):
    """Test plot command when a database exception occurs."""
    mock_connect.side_effect = Exception("Test Plot DB Error")
    result = runner.invoke(analytics_app, ["plot-sentiment", "neg-123"])
    assert "An error occurred" in result.stdout
    assert "Test Plot DB Error" in result.stdout


# --- Test for __main__ block ---

@patch("src.chimera_intel.core.analytics.analytics_app")
def test_main_call(mock_app_call):
    """Test that the main block calls the typer app."""
    # This uses runpy to execute the module as if it were the main script
    import runpy

    # FIX: Mock sys.argv to prevent pytest args from interfering
    test_args = ["src/chimera_intel/core/analytics.py"]
    with patch.dict("sys.modules", {"__main__": MagicMock()}), \
         patch("sys.argv", test_args):
        runpy.run_module("src.chimera_intel.core.analytics", run_name="__main__")

    mock_app_call.assert_called_once()