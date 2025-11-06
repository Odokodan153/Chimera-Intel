# Chimera-Intel/Tests/test_analyst_opsec.py
import pytest
import base64
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

# Import the app to be tested
from chimera_intel.core.analyst_opsec import analyst_opsec_app
# Import the real User schema to create mocks
from chimera_intel.core.schemas import User

runner = CliRunner()

@pytest.fixture
def mock_user_obj():
    """Provides a mock User object for testing."""
    return User(
        id=1,
        username="analyst-007",
        email="test@example.com",
        full_name="Test Analyst",
        hashed_password="abc",
        disabled=False,
        last_login=datetime.now(timezone.utc)
    )

@pytest.fixture
def mock_db_tx():
    """Mocks the database connection and transaction context."""
    # Create mock connection and cursor
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    
    # Make the connection a context manager
    mock_conn_cm = MagicMock()
    mock_conn_cm.__enter__.return_value = mock_conn
    mock_conn_cm.__exit__.return_value = None

    with patch("chimera_intel.core.analyst_opsec.get_db_connection", return_value=mock_conn_cm):
        yield mock_conn, mock_cursor

@patch("chimera_intel.core.analyst_opsec.audit_event")
@patch("chimera_intel.core.analyst_opsec.encrypt_data", return_value=b"encrypted_key_bytes")
@patch("chimera_intel.core.analyst_opsec.update_user_data")
@patch("chimera_intel.core.analyst_opsec.get_user_by_username")
def test_cli_rotate_api_key_success(mock_get_user, mock_update, mock_encrypt, mock_audit, mock_db_tx, mock_user_obj):
    """Tests the 'rotate-key' command with full integration mocks."""
    
    mock_get_user.return_value = mock_user_obj
    mock_conn, mock_cursor = mock_db_tx
    
    result = runner.invoke(
        analyst_opsec_app,
        [
            "rotate-key",
            "analyst-007",
            "--reason", "Scheduled 90-day rotation",
            "--admin-user", "test_admin"
        ],
    )
    
    assert result.exit_code == 0, result.output
    assert "Success!" in result.stdout
    assert "chimera_ak_" in result.stdout
    assert "Warning: This is the only time the key will be shown" in result.stdout
    
    # Check that the user was fetched
    mock_get_user.assert_called_with("analyst-007")
    
    # Check that the key was encrypted
    mock_encrypt.assert_called_once()
    assert mock_encrypt.call_args[0][0].startswith(b"chimera_ak_")
    
    # Check that the DB was updated with the Base64 encoded key
    expected_b64_key = base64.b64encode(b"encrypted_key_bytes").decode('ascii')
    mock_update.assert_called_with(
        "analyst-007", 
        {"api_key_encrypted": expected_b64_key},
        db=mock_cursor
    )
    
    # Check that the audit log was called
    mock_audit.assert_called_with(
        user="test_admin",
        action="analyst_key_rotation",
        target="analyst-007",
        consent_id=None,
        note="Key rotated. Reason: Scheduled 90-day rotation"
    )
    
    # Check that the transaction was committed
    mock_conn.commit.assert_called_once()
    mock_conn.rollback.assert_not_called()

@patch("chimera_intel.core.analyst_opsec.get_user_by_username")
def test_cli_rotate_key_user_not_found(mock_get_user, mock_db_tx):
    """Tests that key rotation fails if the user doesn't exist."""
    mock_get_user.return_value = None
    
    result = runner.invoke(
        analyst_opsec_app,
        ["rotate-key", "ghost_user", "--reason", "test"],
    )
    
    assert result.exit_code == 1
    assert "Error" in result.stdout
    assert "not found" in result.stdout

@patch("chimera_intel.core.analyst_opsec.audit_event")
@patch("chimera_intel.core.analyst_opsec.update_user_data", side_effect=Exception("DB write failed"))
@patch("chimera_intel.core.analyst_opsec.get_user_by_username")
def test_cli_rotate_key_transaction_rollback(mock_get_user, mock_update, mock_audit, mock_db_tx, mock_user_obj):
    """Tests that the transaction is rolled back if any step fails."""
    
    mock_get_user.return_value = mock_user_obj
    mock_conn, mock_cursor = mock_db_tx

    result = runner.invoke(
        analyst_opsec_app,
        [
            "rotate-key",
            "analyst-007",
            "--reason", "A failed attempt"
        ],
    )

    assert result.exit_code == 1
    assert "Transaction Failed" in result.stdout
    assert "DB write failed" in result.stdout
    assert "Operation rolled back" in result.stdout
    
    # Check that the transaction was rolled back
    mock_conn.commit.assert_not_called()
    mock_conn.rollback.assert_called_once()
    mock_audit.assert_not_called() # Should fail before audit

@patch("chimera_intel.core.analyst_opsec.audit_event")
@patch("chimera_intel.core.analyst_opsec.get_user_by_username")
def test_cli_check_session_valid(mock_get_user, mock_audit, mock_user_obj):
    """Tests a valid session by fetching 'last_login' from the user."""
    
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    mock_user_obj.last_login = one_hour_ago
    mock_get_user.return_value = mock_user_obj
    
    result = runner.invoke(
        analyst_opsec_app,
        [
            "check-session",
            "analyst-007",
            "--max-hours", "8"
        ],
    )
    
    assert result.exit_code == 0
    assert "VALID" in result.stdout
    assert "Time Remaining" in result.stdout
    assert "Note: This check is a heuristic" in result.stdout
    mock_get_user.assert_called_with("analyst-007")
    mock_audit.assert_not_called()

@patch("chimera_intel.core.analyst_opsec.audit_event")
@patch("chimera_intel.core.analyst_opsec.get_user_by_username")
def test_cli_check_session_expired(mock_get_user, mock_audit, mock_user_obj):
    """Tests an expired session by fetching 'last_login'."""
    
    ten_hours_ago = datetime.now(timezone.utc) - timedelta(hours=10)
    mock_user_obj.last_login = ten_hours_ago
    mock_get_user.return_value = mock_user_obj
    
    result = runner.invoke(
        analyst_opsec_app,
        [
            "check-session",
            "analyst-007",
            "--max-hours", "8"
        ],
    )
    
    assert result.exit_code == 1 # Command should fail
    assert "EXPIRED" in result.stdout
    assert ten_hours_ago.isoformat() in result.stdout
    
    # Check that the expiration was audited
    mock_audit.assert_called_with(
        user="system_monitor",
        action="session_expired",
        target="analyst-007",
        consent_id=None,
        note="Analyst session exceeded 8 hours."
    )

@patch("chimera_intel.core.analyst_opsec.get_user_by_username")
def test_cli_check_session_no_login_time(mock_get_user, mock_user_obj):
    """Tests a user who has never logged in."""
    
    mock_user_obj.last_login = None
    mock_get_user.return_value = mock_user_obj
    
    result = runner.invoke(
        analyst_opsec_app,
        ["check-session", "analyst-007"],
    )
    
    assert result.exit_code != 0 # Should not succeed
    assert "Warning" in result.stdout
    assert "has no 'last_login' timestamp" in result.stdout