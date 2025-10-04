import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import json

# The application instance to be tested

from chimera_intel.core.attack_path_simulator import attack_path_simulator_app

runner = CliRunner()


@pytest.fixture
def mock_db_with_scans(mocker):
    """Mocks the database session and returns a list of scan objects."""
    mock_scan1 = MagicMock()
    mock_scan1.id = 1
    mock_scan1.module = "footprint"
    mock_scan1.data = {
        "domain": "example.com",
        "footprint": {
            "dns_records": {"A": ["192.168.1.10"]},
            "subdomains": {"results": [{"domain": "api.example.com"}]},
        },
    }

    mock_scan2 = MagicMock()
    mock_scan2.id = 2
    mock_scan2.module = "vulnerability_scanner"
    mock_scan2.data = {
        "ip": "192.168.1.10",
        "scanned_hosts": [
            {
                "host": "192.168.1.10",
                "open_ports": [
                    {
                        "port": 443,
                        "vulnerabilities": [{"id": "CVE-2023-1234", "cvss_score": 9.8}],
                    }
                ],
            }
        ],
    }

    mock_db_session = MagicMock()
    mock_db_session.query.return_value.filter.return_value.all.return_value = [
        mock_scan1,
        mock_scan2,
    ]

    mocker.patch(
        "chimera_intel.core.attack_path_simulator.get_db",
        return_value=iter([mock_db_session]),
    )
    return mock_db_session


def test_build_attack_graph_from_db(mock_db_with_scans):
    """Tests that the attack graph is built with correct nodes and edges."""
    from chimera_intel.core.attack_path_simulator import build_attack_graph_from_db

    graph = build_attack_graph_from_db("test_project")

    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["reason"] == "DNS Resolution: 192.168.1.10"


@patch("chimera_intel.core.attack_path_simulator.perform_generative_task")
def test_simulate_attack_success(mock_perform_generative_task, mock_db_with_scans):
    """Tests the simulate attack command with mocked database and AI call."""
    mock_perform_generative_task.return_value = "AI generated attack path"

    result = runner.invoke(
        attack_path_simulator_app,
        ["attack"],
        input="test_project\nexfiltrate-data\n",  # Input for project name and goal prompts
    )

    assert result.exit_code == 0
    assert "Simulating attack path" in result.stdout
    assert "AI generated attack path" in result.stdout
    mock_perform_generative_task.assert_called_once()


def test_simulate_attack_no_assets(mocker):
    """Tests the command when no assets are found for the project."""
    mock_db_session = MagicMock()
    mock_db_session.query.return_value.filter.return_value.all.return_value = []
    mocker.patch(
        "chimera_intel.core.attack_path_simulator.get_db",
        return_value=iter([mock_db_session]),
    )

    result = runner.invoke(
        attack_path_simulator_app, ["attack"], input="test_project\nexfiltrate-data\n"
    )

    assert result.exit_code == 1
    assert "No assets found for project 'test_project'" in result.stdout
