import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# Import the application instance and the SWOTAnalysisResult schema

from chimera_intel.core.attack_path_simulator import attack_path_app

runner = CliRunner()


@pytest.fixture
def mock_db_connection(mocker):
    """
    Mocks the get_db_connection function and returns a mock cursor
    with predefined connection data.
    """
    # This data simulates the raw rows fetched from the PostgreSQL database

    mock_connections = [
        ("Public-Facing Web Server", "API Gateway"),
        ("API Gateway", "Customer Database"),
    ]

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = mock_connections
    # Ensure fetchone returns a count for the initial asset check

    mock_cursor.fetchone.return_value = (len(mock_connections),)

    # Patch the actual database connection function in the target module

    mocker.patch(
        "chimera_intel.core.attack_path_simulator.get_db_connection",
        return_value=mock_conn,
    )
    return mock_conn, mock_cursor


@patch("chimera_intel.core.config_loader.API_KEYS")
def test_simulate_attack_success(mock_api_keys, mock_db_connection):
    """
    Tests the 'simulate attack' command with mocked database calls.
    """
    # --- Setup Mocks ---

    mock_api_keys.google_api_key = "fake_key"

    # --- Run Command ---

    result = runner.invoke(
        attack_path_app,
        [
            "simulate",
            "--entry-point",
            "Public-Facing Web Server",
            "--target-asset",
            "Customer Database",
        ],
    )

    # --- Assertions ---

    assert result.exit_code == 0
    assert "Simulating attack path" in result.stdout
    assert "Simulated Attack Path(s)" in result.stdout
    assert (
        "Public-Facing Web Server -> API Gateway -> Customer Database" in result.stdout
    )


def test_simulate_attack_no_assets(mocker):
    """
    Tests the command's failure when no assets are found for the project.
    """
    # Mock the database to return no scan data

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchone.return_value = (0,)  # Simulate COUNT(*) returning 0
    mocker.patch(
        "chimera_intel.core.attack_path_simulator.get_db_connection",
        return_value=mock_conn,
    )

    # --- Run Command ---

    result = runner.invoke(
        attack_path_app,
        ["simulate", "--entry-point", "a", "--target-asset", "b"],
    )

    # --- Assertions ---

    assert result.exit_code == 1
    assert "Warning:" in result.stdout
    assert "No assets found in the graph database" in result.stdout
