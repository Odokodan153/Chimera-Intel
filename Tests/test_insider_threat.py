import pytest
from typer.testing import CliRunner
import pandas as pd
from chimera_intel.core.insider_threat import insider_threat_app

runner = CliRunner()


@pytest.fixture
def mock_vpn_log(tmp_path):
    """Creates a mock VPN log file (CSV) for testing."""
    log_path = tmp_path / "vpn.log"
    log_data = {
        "timestamp": [
            "2023-10-27 03:30:00",
            "2023-10-27 09:05:00",
            "2023-10-27 09:10:00",
        ],
        "user": ["user_a", "user_b", "user_a"],
        "ip_address": ["10.0.0.5", "192.168.1.10", "8.8.8.8"],
        "action": ["login", "login", "login"],
    }
    df = pd.DataFrame(log_data)
    df.to_csv(log_path, index=False)
    return str(log_path)


def test_analyze_vpn_logs_flag_anomalies(mock_vpn_log):
    """
    Tests the analyze-vpn-logs command with the --flag-anomalies option.
    """
    result = runner.invoke(
        insider_threat_app,
        ["analyze-vpn-logs", mock_vpn_log, "--flag-anomalies"],
    )

    assert result.exit_code == 0
    assert "Analyzing VPN logs from:" in result.stdout
    assert "Potential Insider Threat Anomalies Detected" in result.stdout
    assert "Unusual Login Time" in result.stdout
    assert "user_a" in result.stdout
    assert "Multiple Locations" in result.stdout


def test_analyze_vpn_logs_file_not_found():
    """
    Tests the command when the specified log file does not exist.
    """
    result = runner.invoke(
        insider_threat_app,
        ["analyze-vpn-logs", "non_existent.log"],
    )

    assert result.exit_code == 1
    assert "Error: Log file not found at 'non_existent.log'" in result.stdout
