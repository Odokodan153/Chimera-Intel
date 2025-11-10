import pytest
import os
import json
from typer.testing import CliRunner
from chimera_intel.core.audit_logger import AuditLogger, AuditLogEntry, GENESIS_HASH, audit_app, AUDIT_LOG_PATH

TEST_LOG_PATH = "test_audit_log.jsonl"

@pytest.fixture
def test_logger():
    """Fixture to create an AuditLogger with a clean test log."""
    if os.path.exists(TEST_LOG_PATH):
        os.remove(TEST_LOG_PATH)
    
    logger = AuditLogger(log_path=TEST_LOG_PATH)
    yield logger
    
    if os.path.exists(TEST_LOG_PATH):
        os.remove(TEST_LOG_PATH)

@pytest.fixture
def cli_runner():
    return CliRunner()

def test_log_action(test_logger: AuditLogger):
    """Test logging a single action."""
    entry = test_logger.log_action("user1", "action1", "SUCCESS", "target1")
    
    assert entry.user == "user1"
    assert entry.action_name == "action1"
    assert entry.status == "SUCCESS"
    assert entry.previous_hash == GENESIS_HASH
    assert entry.entry_hash is not None
    assert entry.entry_hash == entry.calculate_hash()
    
    # Check that the file was written
    with open(TEST_LOG_PATH, "r") as f:
        line = f.readline()
        data = json.loads(line)
        assert data["id"] == entry.id
        assert data["entry_hash"] == entry.entry_hash

def test_log_chaining(test_logger: AuditLogger):
    """Test that hashes are chained correctly."""
    entry1 = test_logger.log_action("user1", "action1", "SUCCESS")
    assert entry1.previous_hash == GENESIS_HASH
    
    entry2 = test_logger.log_action("user2", "action2", "FAILURE")
    assert entry2.previous_hash == entry1.entry_hash
    assert entry2.entry_hash != entry1.entry_hash
    
    entry3 = test_logger.log_action("user1", "action3", "PENDING_REVIEW")
    assert entry3.previous_hash == entry2.entry_hash

def test_verify_chain_success(test_logger: AuditLogger):
    """Test successful verification of a valid chain."""
    test_logger.log_action("user1", "action1", "SUCCESS")
    test_logger.log_action("user2", "action2", "FAILURE")
    test_logger.log_action("user1", "action3", "PENDING_REVIEW")
    
    assert test_logger.verify_chain() == True

def test_verify_chain_tamper_entry(test_logger: AuditLogger):
    """Test detection of a tampered entry."""
    test_logger.log_action("user1", "action1", "SUCCESS")
    test_logger.log_action("user2", "action2", "FAILURE")
    
    # Manually tamper with the log file
    with open(TEST_LOG_PATH, "r") as f:
        lines = f.readlines()
    
    # Modify the first entry's details
    entry_data = json.loads(lines[0])
    entry_data["user"] = "TAMPERED_USER"
    lines[0] = json.dumps(entry_data) + "\n"
    
    with open(TEST_LOG_PATH, "w") as f:
        f.writelines(lines)
        
    # Verification should now fail
    assert test_logger.verify_chain() == False

def test_verify_chain_tamper_link(test_logger: AuditLogger):
    """Test detection of a broken chain link."""
    test_logger.log_action("user1", "action1", "SUCCESS")
    test_logger.log_action("user2", "action2", "FAILURE")
    
    # Manually tamper with the log file
    with open(TEST_LOG_PATH, "r") as f:
        lines = f.readlines()
    
    # Modify the second entry's previous_hash
    entry_data = json.loads(lines[1])
    entry_data["previous_hash"] = "invalid_hash_12345"
    lines[1] = json.dumps(entry_data) + "\n"
    
    with open(TEST_LOG_PATH, "w") as f:
        f.writelines(lines)
        
    # Verification should now fail
    assert test_logger.verify_chain() == False

def test_cli_verify(cli_runner: CliRunner, test_logger: AuditLogger):
    """Test the 'audit verify' CLI command."""
    from chimera_intel.core import audit_logger
    audit_logger.audit_logger_instance = test_logger
    
    test_logger.log_action("cli_user", "cli_test", "SUCCESS")
    
    result = cli_runner.invoke(audit_app, ["verify"])
    assert result.exit_code == 0
    assert "SUCCESS" in result.stdout
    assert "Audit log chain is intact" in result.stdout