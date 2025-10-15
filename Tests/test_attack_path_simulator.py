import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# Import the application instance and the AI result schema

from chimera_intel.core.attack_path_simulator import attack_path_simulator_app
from chimera_intel.core.ai_core import AIResult

runner = CliRunner()


@pytest.fixture
def mock_db_connection(mocker):
    """
    Mocks the get_db_connection function and returns a mock cursor
    with predefined scan data.
    """
    # This data simulates the raw rows fetched from the PostgreSQL database

    mock_scan_data = [
        (
            1,
            "footprint",
            {
                "domain": "example.com",
                "footprint": {
                    "dns_records": {"A": ["192.168.1.10"]},
                    "subdomains": {"results": [{"domain": "api.example.com"}]},
                },
            },
        ),
        (
            2,
            "vulnerability_scanner",
            {
                "ip": "192.168.1.10",
                "scanned_hosts": [
                    {
                        "host": "192.168.1.10",
                        "open_ports": [
                            {
                                "port": 443,
                                "vulnerabilities": [
                                    {"id": "CVE-2023-1234", "cvss_score": 9.8}
                                ],
                            }
                        ],
                    }
                ],
            },
        ),
    ]

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = mock_scan_data

    # Patch the actual database connection function in the target module

    mocker.patch(
        "chimera_intel.core.attack_path_simulator.get_db_connection",
        return_value=mock_conn,
    )
    return mock_conn, mock_cursor


@patch("chimera_intel.core.attack_path_simulator.generate_swot_from_data")
@patch("chimera_intel.core.attack_path_simulator.API_KEYS")
def test_simulate_attack_success(mock_api_keys, mock_generate_swot, mock_db_connection):
    """
    Tests the 'simulate attack' command with mocked database and AI calls.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "fake_key"
    mock_generate_swot.return_value = AIResult(
        analysis_text="Step 1: Exploit CVE-2023-1234 on 192.168.1.10.", error=None
    )

    # --- Run Command ---

    result = runner.invoke(
        attack_path_simulator_app,
        ["attack"],
        input="test_project\nexfiltrate-data\n",  # Provide input for the prompts
    )

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Simulating attack path for project 'test_project'" in result.stdout
    assert "Simulated Attack Path" in result.stdout
    assert "Step 1: Exploit CVE-2023-1234" in result.stdout

    # Verify that the AI function was called with a correctly structured prompt

    mock_generate_swot.assert_called_once()
    prompt_arg = mock_generate_swot.call_args[0][0]
    assert "You are a cybersecurity expert" in prompt_arg
    assert "\"goal\": 'exfiltrate-data'" in prompt_arg
    assert '"type": "footprint"' in prompt_arg
    assert '"reason": "DNS Resolution: 192.168.1.10"' in prompt_arg


def test_simulate_attack_no_assets(mocker):
    """
    Tests the command's failure when no assets are found for the project.
    """
    # Mock the database to return no scan data

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = []  # No assets found
    mocker.patch(
        "chimera_intel.core.attack_path_simulator.get_db_connection",
        return_value=mock_conn,
    )
    mocker.patch(
        "chimera_intel.core.attack_path_simulator.API_KEYS.google_api_key", "fake_key"
    )

    # --- Run Command ---

    result = runner.invoke(
        attack_path_simulator_app, ["attack"], input="empty_project\ngoal\n"
    )

    # --- Assertions ---

    assert result.exit_code == 1
    assert "Error:" in result.stdout
    assert "No assets found for project 'empty_project'" in result.stdout
