import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from chimera_intel.core.multi_domain import correlate_signals, multi_domain_app
from chimera_intel.core.schemas import MultiDomainCorrelationAlert

runner = CliRunner()

# --- Mock Data ---

@pytest.fixture
def mock_db_conn(self):
    """Mocks the database connection and cursor."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn, mock_cursor

def get_mock_sigint_event():
    return {
        "id": 1, "module": "marint_ais_live", "project_name": "Project X",
        "timestamp": datetime.utcnow(),
        "result": {"vessel_name": "Ever Given", "latitude": 30.0, "longitude": 32.5}
    }

def get_mock_humint_report():
    return {
        "id": 2, "module": "humint_report", "project_name": "Project X",
        "timestamp": datetime.utcnow(),
        "result": {"content": "Local sources report a major strike at the port.", "source": "Source Alpha"}
    }

def get_mock_finint_signal():
    return {
        "id": 3, "module": "finint_aml_patterns", "project_name": "Project X",
        "timestamp": datetime.utcnow(),
        "result": {"target": "Suez Canal Authority", "pattern_type": "Anomalous Payment"}
    }

# --- Tests ---

@patch("chimera_intel.core.multi_domain.get_db_connection")
def test_correlate_signals_all_present(mock_get_conn):
    """
    Tests that an alert IS generated when all three signals are present.
    """
    mock_conn = MagicMock()
    mock_get_conn.return_value = mock_conn
    
    # Configure mock cursors for each find function
    with patch("chimera_intel.core.multi_domain.find_recent_sigint", return_value=[get_mock_sigint_event()]), \
         patch("chimera_intel.core.multi_domain.find_recent_humint", return_value=[get_mock_humint_report()]), \
         patch("chimera_intel.core.multi_domain.find_recent_finint", return_value=[get_mock_finint_signal()]), \
         patch("chimera_intel.core.multi_domain.save_scan_to_db") as mock_save:

        alert = correlate_signals(
            project="Project X",
            sigint_modules=["marint_ais_live"],
            humint_keyword="strike",
            finint_entity="Suez Canal Authority",
            max_age_hours=24
        )
        
        assert alert is not None
        assert isinstance(alert, MultiDomainCorrelationAlert)
        assert alert.project == "Project X"
        assert alert.priority == "Critical"
        assert "Confluence of 1 SIGINT" in alert.justification
        assert len(alert.correlated_sigint_events) == 1
        assert len(alert.correlated_humint_reports) == 1
        assert len(alert.correlated_finint_signals) == 1
        assert alert.status == "Pending Analyst Review"
        mock_save.assert_called_once() # Verify it was saved

@patch("chimera_intel.core.multi_domain.get_db_connection")
def test_correlate_signals_missing_humint(mock_get_conn):
    """
    Tests that an alert IS NOT generated when HUMINT is missing.
    """
    mock_conn = MagicMock()
    mock_get_conn.return_value = mock_conn
    
    with patch("chimera_intel.core.multi_domain.find_recent_sigint", return_value=[get_mock_sigint_event()]), \
         patch("chimera_intel.core.multi_domain.find_recent_humint", return_value=[]), \
         patch("chimera_intel.core.multi_domain.find_recent_finint", return_value=[get_mock_finint_signal()]), \
         patch("chimera_intel.core.multi_domain.save_scan_to_db") as mock_save:

        alert = correlate_signals(
            project="Project X",
            sigint_modules=["marint_ais_live"],
            humint_keyword="strike",
            finint_entity="Suez Canal Authority",
            max_age_hours=24
        )
        
        assert alert is None
        mock_save.assert_not_called()

@patch("chimera_intel.core.multi_domain.correlate_signals")
def test_correlate_cli_command(mock_correlate):
    """
    Tests the CLI command interface.
    """
    mock_alert = MultiDomainCorrelationAlert(
        project="Project Y",
        summary="Test Alert",
        confidence=0.9,
        justification="Test Justification"
    )
    mock_correlate.return_value = mock_alert
    
    result = runner.invoke(
        multi_domain_app,
        [
            "correlate",
            "--project", "Project Y",
            "--sigint-module", "test_sigint",
            "--humint-keyword", "test_humint",
            "--finint-entity", "test_finint",
        ],
    )
    
    assert result.exit_code == 0
    assert "Multi-Domain Alert Created" in result.stdout
    assert "Test Alert" in result.stdout
    assert "Test Justification" in result.stdout
    mock_correlate.assert_called_with(
        project="Project Y",
        sigint_modules=["test_sigint"],
        humint_keyword="test_humint",
        finint_entity="test_finint",
        max_age_hours=72
    )