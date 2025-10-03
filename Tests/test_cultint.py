import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# The application instance to be tested
from chimera_intel.core.cultint import cultint_app
from chimera_intel.core.database import Scans

runner = CliRunner()

@pytest.fixture
def mock_db_session(mocker):
    """Mocks the database session with sample scan data."""
    mock_scan_social = Scans(
        id=1, project_name="test-group", module="social_osint", data={"post": "We must protect our digital sovereignty."}
    )
    mock_scan_darkweb = Scans(
        id=2, project_name="test-group", module="dark_web_osint", data={"forum_post": "Centralized control is the enemy."}
    )
    
    mock_query = MagicMock()
    mock_query.filter.return_value.all.return_value = [mock_scan_social, mock_scan_darkweb]
    # Handle the chained .filter() for source selection
    mock_query.filter.return_value.filter.return_value.all.return_value = [mock_scan_social]
    
    mock_db = MagicMock()
    mock_db.query.return_value = mock_query
    
    return mocker.patch('chimera_intel.core.cultint.get_db', return_value=iter([mock_db]))

@patch('chimera_intel.core.cultint.perform_generative_task', return_value="Core Value: Digital Sovereignty.")
def test_cultint_map_success(mock_ai_task, mock_db_session):
    """
    Tests the successful run of the cultint-map command.
    """
    result = runner.invoke(
        cultint_app,
        ["map", "--project", "test-group"],
    )

    assert result.exit_code == 0
    assert "Cultural Terrain Map" in result.stdout
    assert "Core Value: Digital Sovereignty." in result.stdout
    mock_ai_task.assert_called_once()
    # Check that the prompt contains data from the mocked scans
    assert "digital sovereignty" in mock_ai_task.call_args[0][0]
    assert "Centralized control" in mock_ai_task.call_args[0][0]

def test_cultint_map_no_data(mocker):
    """
    Tests the command's behavior when no data is found for the project.
    """
    mock_query = MagicMock()
    mock_query.filter.return_value.all.return_value = [] # No data
    mock_db = MagicMock()
    mock_db.query.return_value = mock_query
    
    mocker.patch('chimera_intel.core.cultint.get_db', return_value=iter([mock_db]))

    result = runner.invoke(
        cultint_app,
        ["map", "--project", "empty-group"],
    )

    assert result.exit_code == 1
    assert "Error: No data found for the specified project and sources." in result.stdout