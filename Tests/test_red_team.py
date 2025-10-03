import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested
from chimera_intel.core.red_team import red_team_app
from chimera_intel.core.database import Scans

runner = CliRunner()

@pytest.fixture
def mock_db_session(mocker):
    """Mocks the database session and returns mock asset data."""
    mock_scan_web = Scans(id=1, project_name="corp-net", module="footprint", data={"domain": "corp.com"})
    mock_scan_personnel = Scans(id=2, project_name="corp-net", module="personnel_osint", data={"employee": "john.doe@corp.com"})
    
    mock_query = MagicMock()
    mock_query.filter.return_value.all.return_value = [mock_scan_web, mock_scan_personnel]
    mock_db = MagicMock()
    mock_db.query.return_value = mock_query
    return mocker.patch('chimera_intel.core.red_team.get_db', return_value=iter([mock_db]))

@patch('chimera_intel.core.red_team.perform_generative_task')
def test_simulate_success(mock_ai_task, mock_db_session):
    """
    Tests the successful run of a Red Team simulation.
    """
    mock_ai_task.return_value = "Stage 1 (Initial Access): Spearphishing Attachment (T1566.001) targeting john.doe@corp.com."

    result = runner.invoke(
        red_team_app,
        ["simulate", "--project", "corp-net", "--adversary", "FIN7"],
    )

    assert result.exit_code == 0
    assert "Red Team Simulation: FIN7 Campaign" in result.stdout
    assert "Spearphishing Attachment (T1566.001)" in result.stdout
    
    # Verify the AI was prompted correctly
    mock_ai_task.assert_called_once()
    prompt_arg = mock_ai_task.call_args[0][0]
    assert "You are an AI-powered Red Team agent" in prompt_arg
    assert "adopt the persona and known tactics of the threat actor group: **FIN7**" in prompt_arg
    assert "john.doe@corp.com" in prompt_arg

def test_simulate_no_assets(mocker):
    """
    Tests the command's failure when no assets are found for the project.
    """
    mock_query = MagicMock()
    mock_query.filter.return_value.all.return_value = [] # No assets
    mock_db = MagicMock()
    mock_db.query.return_value = mock_query
    mocker.patch('chimera_intel.core.red_team.get_db', return_value=iter([mock_db]))

    result = runner.invoke(
        red_team_app,
        ["simulate", "--project", "empty-project", "--adversary", "APT29"],
    )
    
    assert result.exit_code == 1
    assert "Error: No assets found for project 'empty-project'. Cannot run simulation." in result.stdout