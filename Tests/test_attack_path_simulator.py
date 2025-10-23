from typer.testing import CliRunner
import unittest
from unittest.mock import MagicMock, patch
from chimera_intel.core.attack_path_simulator import attack_path_app

runner = CliRunner()


@patch("chimera_intel.core.attack_path_simulator.logger")
@patch("chimera_intel.core.attack_path_simulator.nx.has_path", return_value=True)
@patch("chimera_intel.core.attack_path_simulator.nx.all_shortest_paths")
@patch("chimera_intel.core.attack_path_simulator.console.print", new_callable=MagicMock)
@patch("chimera_intel.core.attack_path_simulator.get_db_connection")
def test_simulate_attack_success(
    mock_get_db_conn, mock_console_print, mock_all_paths, mock_has_path, mock_logger
):
    """
    Tests the 'simulate' command with mocked database calls returning a simple
    chain of connections, and verifies that the simulated path is printed.
    """
    # Setup fake DB cursor/connection
    mock_cursor = MagicMock()
    mock_connections = [
        ("Public-Facing Web Server", "API Gateway"),
        ("API Gateway", "Customer Database"),
    ]
    mock_cursor.fetchall.return_value = mock_connections
    mock_cursor.fetchone.return_value = (len(mock_connections),)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # --- FIX: Mock the .close() methods to prevent AttributeError ---
    mock_cursor.close = MagicMock()
    mock_conn.close = MagicMock()
    # ------------------------------------------------------------

    mock_get_db_conn.return_value = mock_conn
    mock_all_paths.return_value = [
        ["Public-Facing Web Server", "API Gateway", "Customer Database"]
    ]

    # Run the CLI
    # PYTEST_FIX: Remove "simulate" from the invocation.
    result = runner.invoke(
        attack_path_app,
        [
            "--entry-point",
            "Public-Facing Web Server",
            "--target-asset",
            "Customer Database",
        ],
    )

    # Assertions
    assert result.exit_code == 0, result.stdout
    mock_console_print.assert_any_call(
        "Simulating attack path from '[bold cyan]Public-Facing Web Server[/bold cyan]' to '[bold red]Customer Database[/bold red]'..."
    )

    # Check that our nx mocks were called
    mock_has_path.assert_called_with(
        unittest.mock.ANY,
        "Public-Facing Web Server",
        "Customer Database",
    )
    mock_all_paths.assert_called_with(
        unittest.mock.ANY,
        "Public-Facing Web Server",
        "Customer Database",
    )
    found_title_or_panel = any(
        "Simulated Attack Path(s)" in str(call)
        or "Public-Facing Web Server -> API Gateway -> Customer Database" in str(call)
        for call in mock_console_print.mock_calls
    )
    assert found_title_or_panel, "Expected attack path title or string was not printed."

    # DB function was called and queries executed
    mock_get_db_conn.assert_called_once()
    mock_cursor.execute.assert_any_call("SELECT COUNT(*) FROM asset_connections")
    mock_cursor.execute.assert_any_call("SELECT source, target FROM asset_connections")
    
    # --- FIX: Verify that close() was called ---
    mock_cursor.close.assert_called_once()
    mock_conn.close.assert_called_once()
    # ------------------------------------------


@patch("chimera_intel.core.attack_path_simulator.logger")
@patch("chimera_intel.core.attack_path_simulator.console.print", new_callable=MagicMock)
@patch("chimera_intel.core.attack_path_simulator.get_db_connection")
def test_simulate_attack_no_assets(mock_get_db_conn, mock_console_print, mock_logger):
    """
    Tests that the command exits with code 0 and prints a warning when no assets exist.
    """
    # Setup DB mock that returns zero count
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (0,)  # Return 0 for the COUNT(*)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # --- FIX: Mock the .close() methods to prevent AttributeError ---
    mock_cursor.close = MagicMock()
    mock_conn.close = MagicMock()
    # ------------------------------------------------------------

    mock_get_db_conn.return_value = mock_conn

    # PYTEST_FIX: Remove "simulate" from the invocation.
    result = runner.invoke(
        attack_path_app,
        [
            "--entry-point",
            "any",
            "--target-asset",
            "any",
        ],
    )

    # --- FIX: The command now 'return's, so the exit code is 0 ---
    assert result.exit_code == 0, result.stdout
    # ---------------------------------------------------------
    
    mock_console_print.assert_any_call(
        "[bold yellow]Warning:[/bold yellow] No assets found in the graph database. Cannot build attack graph."
    )
    mock_cursor.execute.assert_any_call("SELECT COUNT(*) FROM asset_connections")
    
    # --- FIX: Verify that close() was called before returning ---
    mock_cursor.close.assert_called_once()
    mock_conn.close.assert_called_once()
    # ----------------------------------------------------------