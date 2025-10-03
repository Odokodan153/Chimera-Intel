import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested

from chimera_intel.core.attack_path_simulator import attack_path_simulator_app
from chimera_intel.core.database import Scans

runner = CliRunner()


@pytest.fixture
def mock_db_session(mocker):
    """Mocks the database session and query."""
    mock_scan_1 = Scans(
        id=1,
        project_name="test-project",
        module="footprint",
        data={"domain": "example.com"},
    )
    mock_scan_2 = Scans(
        id=2,
        project_name="test-project",
        module="recon",
        data={"ip": "1.2.3.4", "ports": [80, 443]},
    )

    mock_query = MagicMock()
    mock_query.filter.return_value.all.return_value = [mock_scan_1, mock_scan_2]

    mock_db = MagicMock()
    mock_db.query.return_value = mock_query

    return mocker.patch(
        "chimera_intel.core.attack_path_simulator.get_db", return_value=iter([mock_db])
    )


@pytest.fixture
def mock_ai_task(mocker):
    """Mocks the AI core's generative task function."""
    return mocker.patch(
        "chimera_intel.core.attack_path_simulator.perform_generative_task",
        return_value="Step 1: Exploit web server on 1.2.3.4. Step 2: Access domain data on example.com.",
    )


def test_simulate_attack_success(mock_db_session, mock_ai_task):
    """
    Tests the simulate-attack command with a successful simulation using mock DB data.
    """
    result = runner.invoke(
        attack_path_simulator_app,
        ["attack", "--project", "test-project", "--goal", "exfiltrate-data"],
    )

    assert result.exit_code == 0
    assert "Simulating attack path for project 'test-project'" in result.stdout
    assert "Simulated Attack Path" in result.stdout
    assert "Step 1: Exploit web server" in result.stdout
    mock_db_session.assert_called_once()


def test_simulate_attack_no_assets(mocker):
    """
    Tests the command's behavior when no assets are found for the project.
    """
    mock_query = MagicMock()
    mock_query.filter.return_value.all.return_value = []

    mock_db = MagicMock()
    mock_db.query.return_value = mock_query

    mocker.patch(
        "chimera_intel.core.attack_path_simulator.get_db", return_value=iter([mock_db])
    )

    result = runner.invoke(
        attack_path_simulator_app,
        ["attack", "--project", "empty-project", "--goal", "any-goal"],
    )

    assert result.exit_code == 1
    assert (
        "Error: No assets found for project 'empty-project'. Run scans first."
        in result.stdout
    )
