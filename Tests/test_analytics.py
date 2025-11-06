import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
from typer.testing import CliRunner
import unittest
from datetime import datetime
from src.chimera_intel.core.analytics import get_negotiation_kpis, get_quick_win_metrics
from src.chimera_intel.core.analytics_cli import analytics_app

# --- End Fix ---

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


# FIX: Patch the API_KEYS object *where it is used* (in analytics_cli)
@patch(
    "src.chimera_intel.core.analytics_cli.API_KEYS",
    MagicMock(db_name=None, db_user=None, db_password=None, db_host=None),
)
# --- FIX: Remove unnecessary mocks for this validation test ---
def test_plot_sentiment_missing_params():
    """Test plot command when DB parameters are missing from config."""
    # The patch decorator above already sets database_url to None
    result = runner.invoke(analytics_app, ["plot-sentiment", "neg-123"])
    assert "Error: Database connection parameters are missing." in result.stdout


# FIX: Patch target to 'analytics_cli.API_KEYS' and provide 'database_url'
@patch(
    "src.chimera_intel.core.analytics_cli.API_KEYS",
    MagicMock(
        db_name="testdb",
        db_user="testuser",
        db_password="testpass",
        db_host="localhost",
    ),
)
# --- FIX: Update patch targets to point to analytics_cli ---
@patch("src.chimera_intel.core.analytics_cli.psycopg2.connect")
@patch("src.chimera_intel.core.analytics_cli.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics_cli.plt")
# --- End Fix ---
def test_plot_sentiment_connection_error(mock_plt, mock_read_sql, mock_connect):
    """Test plot command when DB connection fails."""
    mock_connect.return_value = None
    result = runner.invoke(analytics_app, ["plot-sentiment", "neg-123"])
    assert "Error: Could not connect to the database." in result.stdout


# FIX: Patch target to 'analytics_cli.API_KEYS' and provide 'database_url'
@patch(
    "src.chimera_intel.core.analytics_cli.API_KEYS",
    MagicMock(
        db_name="testdb",
        db_user="testuser",
        db_password="testpass",
        db_host="localhost",
    ),
)
# --- FIX: Update patch targets to point to analytics_cli ---
@patch("src.chimera_intel.core.analytics_cli.psycopg2.connect")
@patch("src.chimera_intel.core.analytics_cli.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics_cli.plt")
# --- End Fix ---
def test_plot_sentiment_no_messages(
    mock_plt, mock_read_sql, mock_connect, mock_db_conn
):
    """Test plot command when no messages are found for the negotiation ID."""
    mock_connect.return_value = mock_db_conn[0]
    # Simulate empty DataFrame
    mock_read_sql.return_value = pd.DataFrame(columns=["timestamp", "sentiment"])

    result = runner.invoke(analytics_app, ["plot-sentiment", "neg-404"])
    assert "No messages found for negotiation ID: neg-404" in result.stdout


# FIX: Patch target to 'analytics_cli.API_KEYS' and provide 'database_url'
@patch(
    "src.chimera_intel.core.analytics_cli.API_KEYS",
    MagicMock(
        db_name="testdb",
        db_user="testuser",
        db_password="testpass",
        db_host="localhost",
    ),
)
# --- FIX: Update patch targets to point to analytics_cli ---
@patch("src.chimera_intel.core.analytics_cli.psycopg2.connect")
@patch("src.chimera_intel.core.analytics_cli.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics_cli.plt")
# --- End Fix ---
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
    mock_plt.plot.assert_called_with(
        df["timestamp"], df["sentiment"], marker="o", linestyle="-"
    )
    mock_plt.savefig.assert_called_with("test_plot.png")
    mock_plt.show.assert_not_called()


# FIX: Patch target to 'analytics_cli.API_KEYS' and provide 'database_url'
@patch(
    "src.chimera_intel.core.analytics_cli.API_KEYS",
    MagicMock(
        db_name="testdb",
        db_user="testuser",
        db_password="testpass",
        db_host="localhost",
    ),
)
# --- FIX: Update patch targets to point to analytics_cli ---
@patch("src.chimera_intel.core.analytics_cli.psycopg2.connect")
@patch("src.chimera_intel.core.analytics_cli.pd.read_sql_query")
@patch("src.chimera_intel.core.analytics_cli.plt")
# --- End Fix ---
def test_plot_sentiment_show_plot(mock_plt, mock_read_sql, mock_connect, mock_db_conn):
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


# FIX: Patch target to 'analytics_cli.API_KEYS' and provide 'database_url'
@patch(
    "src.chimera_intel.core.analytics_cli.API_KEYS",
    MagicMock(
        db_name="testdb",
        db_user="testuser",
        db_password="testpass",
        db_host="localhost",
    ),
)
# --- FIX: Update patch targets to point to analytics_cli ---
@patch("src.chimera_intel.core.analytics_cli.psycopg2.connect")
@patch("src.chimera_intel.core.analytics_cli.pd.read_sql_query")
# --- End Fix ---
def test_plot_sentiment_db_exception(mock_read_sql, mock_connect):
    """Test plot command when a database exception occurs."""
    mock_connect.side_effect = Exception("Test Plot DB Error")
    result = runner.invoke(analytics_app, ["plot-sentiment", "neg-123"])
    assert "An error occurred" in result.stdout
    assert "Test Plot DB Error" in result.stdout

class TestQuickWinMetrics(unittest.TestCase):

    @patch("chimera_intel.core.analytics.psycopg2.connect")
    def test_get_quick_win_metrics_full(self, mock_connect):
        """
        Test the successful calculation of all quick-win metrics.
        """
        # --- Mock Data Setup ---
        project_name = "test-project"
        project_start_time = datetime(2023, 1, 1, 12, 0, 0)
        
        # Metric 1: TTFD
        # Scan 1: Baseline
        scan1_time = datetime(2023, 1, 2, 12, 0, 0)
        scan1_result = {
            "footprint": {
                "subdomains": {
                    "results": [{"domain": "www.example.com", "sources": ["source1"]}]
                }
            }
        }
        # Scan 2: New subdomain found
        scan2_time = datetime(2023, 1, 3, 14, 0, 0) # 26 hours after project start
        scan2_result = {
            "footprint": {
                "subdomains": {
                    "results": [
                        {"domain": "www.example.com", "sources": ["source1"]},
                        {"domain": "new.example.com", "sources": ["source2"]} # New
                    ],
                    "total_unique": 2
                }
            }
        }
        
        # Metric 2: Corroboration
        # One finding with 1 source, one with 2 sources. Rate = 50%
        scan3_result = {
            "web_analysis": {
                "tech_stack": {
                    "results": [
                        {"technology": "React", "sources": ["source1", "source2"]}, # Corroborated
                        {"technology": "Nginx", "sources": ["source1"]} # Not
                    ]
                }
            }
        }
        
        # Metric 3: FP Rate
        # 'playbook-1': 1 FP / 2 Total = 50%
        # 'playbook-2': 0 FP / 1 Total = 0%
        mock_fp_records = [
            ("playbook-1", 1, 2),
            ("playbook-2", 0, 1)
        ]
        
        # Metric 4: MTTC
        # Avg 7200 seconds = 2 hours
        mock_mttc_record = (7200.0,)
        
        # Metric 5: Coverage
        # From scan2_result, total_unique is 2
        
        # --- Mock DB Configuration ---
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        # Configure mock responses for each query
        mock_cursor.execute.side_effect = [
            # 1. Check project exists
            lambda query, args: None if "SELECT id FROM projects" in query else None,
            # 2. Get project start time (for TTFD)
            lambda query, args: None if "SELECT created_at FROM projects" in query else None,
            # 3. Get footprint scans (for TTFD)
            lambda query, args: None if "SELECT result, timestamp FROM scan_results" in query and "footprint" in query else None,
            # 4. Get all scans (for Corroboration)
            lambda query, args: None if "SELECT result FROM scan_results" in query and "WHERE project_name" in query else None,
            # 5. Get FP rates
            lambda query, args: None if "SELECT alert_type" in query else None,
            # 6. Get MTTC
            lambda query, args: None if "SELECT AVG(EXTRACT(EPOCH" in query else None,
            # 7. Get Asset Coverage
            lambda query, args: None if "SELECT result FROM scan_results" in query and "LIMIT 1" in query else None,
        ]
        
        mock_cursor.fetchone.side_effect = [
            # 1. Project exists
            ("project-id-123",),
            # 2. Project start time
            (project_start_time,),
            # 6. MTTC result
            mock_mttc_record,
            # 7. Asset Coverage result
            (scan2_result,),
        ]
        
        mock_cursor.fetchall.side_effect = [
            # 3. Footprint scans for TTFD
            [(scan1_result, scan1_time), (scan2_result, scan2_time)],
            # 4. All scans for Corroboration
            [(scan1_result,), (scan2_result,), (scan3_result,)],
            # 5. FP rate results
            mock_fp_records,
        ]

        # --- Run the Function ---
        db_params = {"host": "db", "user": "user", "password": "pw", "dbname": "db"}
        result = get_quick_win_metrics(db_params, project_name)

        # --- Assertions ---
        self.assertIsNone(result.error)
        self.assertEqual(result.project_name, project_name)
        
        # Metric 1: TTFD (2023-01-03 14:00 - 2023-01-01 12:00) = 50 hours
        self.assertEqual(result.time_to_first_subdomain_discovery_hours, 50.0) 
        
        # Metric 2: Corroboration (1/3 findings = 33.33%)
        # scan1: 1 finding, 1 source
        # scan2: 2 findings, 1 source each
        # scan3: 2 findings, 1 w/ 2 sources, 1 w/ 1 source
        # Total findings = 1+2+2 = 5. Corroborated = 1. Rate = 20.0%
        self.assertEqual(result.corroboration_rate_percent, 20.0)
        
        # Metric 3: FP Rate
        self.assertEqual(result.false_positive_rate_by_playbook, {"playbook-1": 50.0, "playbook-2": 0.0})
        
        # Metric 4: MTTC
        self.assertEqual(result.mean_time_to_close_alert_hours, 2.0)
        
        # Metric 5: Asset Coverage
        self.assertEqual(result.total_unique_subdomains_found, 2)

    @patch("chimera_intel.core.analytics.psycopg2.connect")
    def test_metrics_no_project(self, mock_connect):
        """Test behavior when the project does not exist."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        
        # Project not found
        mock_cursor.fetchone.return_value = None 
        
        db_params = {"host": "db", "user": "user", "password": "pw", "dbname": "db"}
        result = get_quick_win_metrics(db_params, "nonexistent-project")
        
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error, "Project 'nonexistent-project' not found.")

    @patch("chimera_intel.core.analytics.psycopg2.connect")
    def test_metrics_no_data(self, mock_connect):
        """Test behavior when there is no scan data."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.execute.side_effect = [
            lambda query, args: None, # Project check
            lambda query, args: None, # TTFD start time
            lambda query, args: None, # TTFD scans
            lambda query, args: None, # Corroboration scans
            lambda query, args: None, # FP rates
            lambda query, args: None, # MTTC
            lambda query, args: None, # Coverage
        ]
        
        mock_cursor.fetchone.side_effect = [
            ("project-id-123",),                     # Project exists
            (datetime(2023, 1, 1, 12, 0, 0),),       # Project start time
            (None,),                                 # MTTC = no data
            (None,),                                 # Coverage = no data
        ]
        
        mock_cursor.fetchall.side_effect = [
            [], # TTFD scans
            [], # Corroboration scans
            [], # FP rates
        ]

        db_params = {"host": "db", "user": "user", "password": "pw", "dbname": "db"}
        result = get_quick_win_metrics(db_params, "empty-project")
        
        self.assertIsNone(result.error)
        self.assertIsNone(result.time_to_first_subdomain_discovery_hours)
        self.assertEqual(result.corroboration_rate_percent, 0.0)
        self.assertEqual(result.false_positive_rate_by_playbook, {})
        self.assertEqual(result.mean_time_to_close_alert_hours, 0.0)
        self.assertEqual(result.total_unique_subdomains_found, 0)
