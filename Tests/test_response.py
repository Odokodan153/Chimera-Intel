import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from chimera_intel.core.response import response_app

# Create a CliRunner instance to invoke the Typer app


runner = CliRunner()


@pytest.fixture
def mock_db_connection(mocker):
    """
    Mocks the get_db_connection function to prevent actual database calls.
    This fixture simulates the connection and cursor objects returned by psycopg2.
    """
    # Create mock objects for the connection and cursor

    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    # Configure the mocks to behave like real psycopg2 objects

    mock_conn.cursor.return_value = mock_cursor

    # Pre-configure the mock cursor for the simulate-event test
    # This simulates finding a rule in the database

    mock_cursor.fetchone.return_value = (["send_slack_alert", "quarantine_host"],)

    # Patch the get_db_connection function in the response module

    mocker.patch(
        "chimera_intel.core.response.get_db_connection", return_value=mock_conn
    )

    return mock_conn, mock_cursor


def test_add_rule_success(mock_db_connection):
    """
    Tests the successful addition of a new response rule via the 'add-rule' command.
    """
    mock_conn, mock_cursor = mock_db_connection

    # Invoke the 'add-rule' command with the required options

    result = runner.invoke(
        response_app,
        [
            "add-rule",
            "--trigger",
            "dark-web:credential-leak",
            "--action",
            "reset_password",
            "--action",
            "send_slack_alert",
        ],
    )

    # --- Assertions ---
    # 1. The command should exit with a code of 0, indicating success.

    assert result.exit_code == 0

    # 2. The success message should be present in the command's output.

    assert "Successfully added/updated response rule." in result.stdout

    # 3. Verify that the correct SQL query was executed to insert/update the rule.

    mock_cursor.execute.assert_called_once()
    # Get the arguments passed to the execute method

    sql_query, params = mock_cursor.execute.call_args[0]
    # Check if the query and parameters are correct

    assert "INSERT INTO response_rules" in sql_query
    assert params[0] == "dark-web:credential-leak"
    assert "reset_password" in params[1]
    assert "send_slack_alert" in params[1]

    # 4. Verify that the transaction was committed to the database.

    mock_conn.commit.assert_called_once()


def test_simulate_event_rule_found(mock_db_connection):
    """
    Tests the 'simulate-event' command for a trigger that has a matching rule.
    """
    mock_conn, mock_cursor = mock_db_connection

    # Invoke the 'simulate-event' command

    result = runner.invoke(
        response_app, ["simulate-event", "test:trigger", "Simulated event details"]
    )

    # --- Assertions ---
    # 1. The command should exit successfully.

    assert result.exit_code == 0

    # 2. Check that the output indicates the event was detected.

    assert "Event detected with trigger:" in result.stdout
    assert "test:trigger" in result.stdout

    # 3. Check that the predefined actions for the trigger were executed.

    assert "Running action: [bold green]send_slack_alert[/bold green]" in result.stdout
    assert "Running action: [bold green]quarantine_host[/bold green]" in result.stdout


def test_simulate_event_no_rule(mock_db_connection):
    """
    Tests the 'simulate-event' command for a trigger that does NOT have a matching rule.
    """
    mock_conn, mock_cursor = mock_db_connection

    # Configure the mock cursor to return None, simulating no rule found

    mock_cursor.fetchone.return_value = None

    # Invoke the 'simulate-event' command

    result = runner.invoke(response_app, ["simulate-event", "unknown:trigger"])

    # --- Assertions ---
    # 1. The command should exit successfully.

    assert result.exit_code == 0

    # 2. The output should clearly state that no rule was found.

    assert "No response rule found for trigger 'unknown:trigger'" in result.stdout
    assert "No actions taken" in result.stdout

    # 3. Ensure no actions were printed as "Executing".

    assert "Executing response actions:" not in result.stdout
