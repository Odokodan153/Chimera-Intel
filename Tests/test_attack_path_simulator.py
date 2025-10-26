from typer.testing import CliRunner
import unittest
from unittest.mock import MagicMock, patch
from chimera_intel.core.attack_path_simulator import attack_path_app
from rich.panel import Panel
import psycopg2  # Import to mock its errors
import networkx as nx  # Import to mock its errors

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
    mock_cursor.close = MagicMock()
    mock_conn.close = MagicMock()
    mock_get_db_conn.return_value = mock_conn
    mock_all_paths.return_value = [
        ["Public-Facing Web Server", "API Gateway", "Customer Database"]
    ]

    # Run the CLI
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

    # Check for Panel output
    found_title_or_panel = False
    for call in mock_console_print.call_args_list:
        if not call[0]:
            continue
        arg = call[0][0]
        if isinstance(arg, Panel):
            panel_title = str(arg.title)
            panel_content = str(arg.renderable)
            if "Simulated Attack Path(s)" in panel_title or \
               "Public-Facing Web Server -> API Gateway -> Customer Database" in panel_content:
                found_title_or_panel = True
                break
    
    assert found_title_or_panel, f"Expected attack path title or string was not printed. Mock calls: {mock_console_print.call_args_list}"

    mock_get_db_conn.assert_called_once()
    mock_cursor.execute.assert_any_call("SELECT COUNT(*) FROM asset_connections")
    mock_cursor.execute.assert_any_call("SELECT source, target FROM asset_connections")
    mock_cursor.close.assert_called_once()
    mock_conn.close.assert_called_once()


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
    mock_cursor.close = MagicMock()
    mock_conn.close = MagicMock()
    mock_get_db_conn.return_value = mock_conn

    # Run the CLI
    result = runner.invoke(
        attack_path_app,
        [
            "--entry-point",
            "any",
            "--target-asset",
            "any",
        ],
    )

    # The command 'return's, so the exit code is 0
    assert result.exit_code == 0, result.stdout
    
    mock_console_print.assert_any_call(
        "[bold yellow]Warning:[/bold yellow] No assets found in the graph database. Cannot build attack graph."
    )
    mock_cursor.execute.assert_any_call("SELECT COUNT(*) FROM asset_connections")
    mock_cursor.close.assert_called_once()
    mock_conn.close.assert_called_once()

# --- Extended Test ---
@patch("chimera_intel.core.attack_path_simulator.logger")
@patch("chimera_intel.core.attack_path_simulator.nx.has_path", return_value=False)
@patch("chimera_intel.core.attack_path_simulator.console.print", new_callable=MagicMock)
@patch("chimera_intel.core.attack_path_simulator.get_db_connection")
def test_simulate_attack_no_path(
    mock_get_db_conn, mock_console_print, mock_has_path, mock_logger
):
    """
    Tests the 'simulate' command when the assets exist but no path is found.
    """
    # Setup fake DB cursor/connection
    mock_cursor = MagicMock()
    mock_connections = [
        ("Server A", "Server B"),
        ("Server C", "Server D"),
    ]
    mock_cursor.fetchall.return_value = mock_connections
    mock_cursor.fetchone.return_value = (len(mock_connections),)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.close = MagicMock()
    mock_conn.close = MagicMock()
    mock_get_db_conn.return_value = mock_conn

    # Run the CLI
    result = runner.invoke(
        attack_path_app,
        [
            "--entry-point",
            "Server A",
            "--target-asset",
            "Server D",
        ],
    )

    # Exits with code 0 after printing the warning
    assert result.exit_code == 0, result.stdout
    mock_has_path.assert_called_with(unittest.mock.ANY, "Server A", "Server D")
    mock_console_print.assert_any_call(
        "[bold yellow]No potential attack path found from 'Server A' to 'Server D'.[/bold yellow]"
    )


# --- Extended Test ---
@patch("chimera_intel.core.attack_path_simulator.logger")
@patch("chimera_intel.core.attack_path_simulator.console.print", new_callable=MagicMock)
@patch("chimera_intel.core.attack_path_simulator.get_db_connection")
def test_simulate_attack_db_error(mock_get_db_conn, mock_console_print, mock_logger):
    """
    Tests the 'simulate' command when the database connection fails.
    Covers the 'except (psycopg2.Error, ConnectionError)' block.
    """
    # Arrange
    mock_get_db_conn.side_effect = psycopg2.Error("Database connection failed")

    # Run the CLI
    result = runner.invoke(
        attack_path_app,
        [
            "--entry-point",
            "any",
            "--target-asset",
            "any",
        ],
    )

    # Assert
    assert result.exit_code == 1, result.stdout
    mock_console_print.assert_any_call(
        "[bold red]Database Error:[/bold red] Database connection failed"
    )


# --- Extended Test ---
@patch("chimera_intel.core.attack_path_simulator.logger")
@patch("chimera_intel.core.attack_path_simulator.nx.has_path")
@patch("chimera_intel.core.attack_path_simulator.console.print", new_callable=MagicMock)
@patch("chimera_intel.core.attack_path_simulator.get_db_connection")
def test_simulate_attack_node_not_found(
    mock_get_db_conn, mock_console_print, mock_has_path, mock_logger
):
    """
    Tests the 'simulate' command when an asset is not in the graph.
    Covers the 'except nx.NodeNotFound' block.
    """
    # Setup fake DB
    mock_cursor = MagicMock()
    mock_connections = [("Server A", "Server B")]
    mock_cursor.fetchall.return_value = mock_connections
    mock_cursor.fetchone.return_value = (len(mock_connections),)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.close = MagicMock()
    mock_conn.close = MagicMock()
    mock_get_db_conn.return_value = mock_conn

    # Arrange
    mock_has_path.side_effect = nx.NodeNotFound("Node 'Nonexistent Asset' not in graph")

    # Run the CLI
    result = runner.invoke(
        attack_path_app,
        [
            "--entry-point",
            "Server A",
            "--target-asset",
            "Nonexistent Asset",
        ],
    )

    # Assert
    assert result.exit_code == 1, result.stdout
    mock_console_print.assert_any_call(
        "[bold red]Asset Not Found:[/bold red] Node 'Nonexistent Asset' not in graph. Ensure the entry point and target exist in the asset graph."
    )