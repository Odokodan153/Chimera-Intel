import pytest
import os
import json
from typer.testing import CliRunner
from chimera_intel.core.alert_manager import AlertManager, AlertLevel, Alert, alert_app, ALERT_DB_PATH

TEST_DB_PATH = "test_alerts.jsonl"

@pytest.fixture
def test_manager():
    """Fixture to create an AlertManager with a clean test DB."""
    # Setup: ensure file is empty
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    
    manager = AlertManager(db_path=TEST_DB_PATH)
    
    yield manager
    
    # Teardown: remove the test file
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

@pytest.fixture
def cli_runner():
    """Fixture for Typer CLI runner."""
    return CliRunner()

def test_dispatch_alert(test_manager: AlertManager):
    """Test dispatching a single alert."""
    assert test_manager.get_alerts() == []
    
    alert = test_manager.dispatch_alert(
        title="Test Alert",
        message="This is a test.",
        level=AlertLevel.CRITICAL,
        confidence=95,
        provenance={"module": "test_alert_manager"},
        legal_flag="TEST_FLAG"
    )
    
    assert alert.title == "Test Alert"
    assert alert.confidence == 95
    assert alert.legal_flag == "TEST_FLAG"
    assert alert.provenance == {"module": "test_alert_manager"}
    
    alerts = test_manager.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].id == alert.id
    assert alerts[0].message == "This is a test."

def test_get_alerts_file_persistence(test_manager: AlertManager):
    """Test that alerts are saved to and read from the file."""
    alert1 = test_manager.dispatch_alert("Alert 1", "Msg 1", AlertLevel.INFO)
    alert2 = test_manager.dispatch_alert("Alert 2", "Msg 2", AlertLevel.WARNING)
    
    # Create a new manager instance to read from the same file
    new_manager = AlertManager(db_path=TEST_DB_PATH)
    alerts = new_manager.get_alerts()
    
    assert len(alerts) == 2
    alert_ids = {a.id for a in alerts}
    assert alert1.id in alert_ids
    assert alert2.id in alert_ids

def test_cli_list_alerts(cli_runner: CliRunner, test_manager: AlertManager):
    """Test the 'alerts list' CLI command."""
    # Patch the global instance used by the CLI
    from chimera_intel.core import alert_manager
    alert_manager.alert_manager_instance = test_manager
    
    # Test empty list
    result = cli_runner.invoke(alert_app, ["list"])
    assert result.exit_code == 0
    assert "No alerts found" in result.stdout
    
    # Add alerts
    test_manager.dispatch_alert("Critical Test", "High severity", AlertLevel.CRITICAL)
    test_manager.dispatch_alert("Info Test", "Low severity", AlertLevel.INFO)
    
    # Test full list
    result = cli_runner.invoke(alert_app, ["list"])
    assert result.exit_code == 0
    assert "Critical Test" in result.stdout
    assert "Info Test" in result.stdout