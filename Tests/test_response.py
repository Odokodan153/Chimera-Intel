import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from chimera_intel.core.response import response_app
import json

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


def test_simulate_event_rule_found(mock_db_connection, capsys):
    """
    Tests the 'simulate-event' command for a trigger that has a matching rule.
    """
    mock_conn, mock_cursor = mock_db_connection
    
    # Configure fetchone to return our desired rule
    mock_cursor.fetchone.return_value = (["send_slack_alert", "quarantine_host"],)


    # Invoke the 'simulate-event' command
    details = {"target": "test-host"}
    result = runner.invoke(
        response_app, ["simulate-event", "test:trigger", json.dumps(details)]
    )
    
    # Capture stdout
    captured = capsys.readouterr()
    
    # --- Assertions ---
    # 1. The command should exit successfully.
    assert result.exit_code == 0

    # 2. Check that the output indicates the event was detected.
    assert "Event detected with trigger:" in captured.out
    assert "test:trigger" in captured.out

    # 3. Check that the predefined actions for the trigger were executed
    # These print to console via the ACTION_MAP mocks
    assert "ACTION (Alert):" in captured.out
    assert "ACTION (Quarantine):" in captured.out
    assert "SKIPPED (SLACK_WEBHOOK_URL not set)" in captured.out
    assert "SKIPPED (EDR API not configured)" in captured.out


def test_simulate_event_no_rule(mock_db_connection):
    """
    Tests the 'simulate-event' command for a trigger that does NOT have a matching rule.
    """
    mock_conn, mock_cursor = mock_db_connection

    # Configure the mock cursor to return None, simulating no rule found

    mock_cursor.fetchone.return_value = None

    # Invoke the 'simulate-event' command

    result = runner.invoke(response_app, ["simulate-event", "unknown:trigger", "{}"])

    # --- Assertions ---
    # 1. The command should exit successfully.

    assert result.exit_code == 0

    # 2. The output should clearly state that no rule was found.

    assert "No response rule found for trigger 'unknown:trigger'" in result.stdout
    assert "No actions taken" in result.stdout

    # 3. Ensure no actions were printed as "Executing".

    assert "Executing response actions:" not in result.stdout

# --- New Test for Malware Sandbox ---

def test_malware_sandbox_command_success(mocker):
    """
    Tests the 'malware-sandbox' command directly.
    """
    # We use runner.isolated_filesystem() to create a temp file
    with runner.isolated_filesystem():
        # Create a dummy file
        with open("suspicious.exe", "w") as f:
            f.write("dummy malware content")
            
        # Mock DOCKER_HOST to be None so it skips Docker logic
        mocker.patch("chimera_intel.core.response.DOCKER_HOST", None)
        
        result = runner.invoke(
            response_app,
            ["malware-sandbox", "suspicious.exe"]
        )
        
        # Assertions
        assert result.exit_code == 0
        assert "--- Malware Sandbox Analysis ---" in result.stdout
        assert "ACTION (Sandbox):" in result.stdout
        assert "SKIPPED (DOCKER_HOST not set)" in result.stdout
        assert "File to analyze:" in result.stdout
        assert "suspicious.exe" in result.stdout
        assert "SHA256:" in result.stdout

def test_malware_sandbox_command_file_not_found(mocker):
    """
    Tests the 'malware-sandbox' command fails if the file doesn't exist.
    """
    result = runner.invoke(
        response_app,
        ["malware-sandbox", "nonexistent.file"]
    )
    
    # Assertions
    assert result.exit_code != 0
    assert "Invalid value" in result.stderr
    assert "does not exist" in result.stderr

def test_execute_action_malware_sandbox(mock_db_connection, capsys):
    """
    Tests the 'malware_sandbox' action when triggered by 'simulate-event'.
    """
    mock_conn, mock_cursor = mock_db_connection
    
    # Configure fetchone to return a rule with the new action
    mock_cursor.fetchone.return_value = (["malware_sandbox"],)
    
    with runner.isolated_filesystem():
        with open("eicar.com", "w") as f:
            f.write("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        
        details = {"file_path": "eicar.com"}
        
        result = runner.invoke(
            response_app, ["simulate-event", "malware:detected", json.dumps(details)]
        )
        
        captured = capsys.readouterr()

        # Assertions
        assert result.exit_code == 0
        assert "Event detected with trigger:" in captured.out
        assert "malware:detected" in captured.out
        assert "Running action: [bold green]malware_sandbox[/bold green]" in captured.out
        assert "ACTION (Sandbox):" in captured.out
        assert "Analysis complete." in captured.out
        assert "ioc_filename" in captured.out