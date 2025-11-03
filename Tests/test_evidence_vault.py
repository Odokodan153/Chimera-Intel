import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import os
from cryptography.fernet import Fernet

# Import the module to be tested
from chimera_intel.core.evidence_vault import (
    vault_app, 
    encrypt_data, 
    decrypt_data, 
    store_evidence, 
    retrieve_evidence
)
from chimera_intel.cli import app # We need the main app to test the command

runner = CliRunner()

@pytest.fixture(scope="module")
def fernet_key():
    """Generate a Fernet key for testing."""
    return Fernet.generate_key()

@pytest.fixture
def mock_env(monkeypatch, fernet_key):
    """Mock the environment variable for the encryption key."""
    monkeypatch.setenv("EVIDENCE_VAULT_KEY", fernet_key.decode())

@pytest.fixture
def mock_db_calls():
    """Mock all database and data_custodian calls."""
    with patch("chimera_intel.core.evidence_vault.create_data_receipt") as mock_create_receipt, \
         patch("chimera_intel.core.evidence_vault.save_scan_to_db") as mock_save, \
         patch("chimera_intel.core.evidence_vault.get_scan_from_db") as mock_get:
        
        # Mock for create_data_receipt
        mock_receipt = MagicMock()
        mock_receipt.receipt_id = "R-test-123"
        mock_create_receipt.return_value = mock_receipt
        
        # Mock for get_scan_from_db
        mock_get.side_effect = [
            # First call (in retrieve_evidence for receipt)
            {
                "receipt_id": "R-test-123",
                "target": "test-target",
                "module": "data_custodian",
                "data": {"chain_of_custody": []}
            },
            # Second call (in retrieve_evidence for vault blob)
            {
                "receipt_id": "R-test-123",
                "module": "evidence_vault",
                "data": {
                    "encrypted_blob": Fernet(os.environ["EVIDENCE_VAULT_KEY"].encode()).encrypt(b"secret data").decode('latin-1')
                }
            }
        ]
        
        yield mock_create_receipt, mock_save, mock_get

# --- Unit Tests ---

def test_encryption_decryption(mock_env):
    original_data = b"This is a top secret message."
    encrypted = encrypt_data(original_data)
    assert original_data != encrypted
    
    decrypted = decrypt_data(encrypted)
    assert original_data == decrypted

def test_decrypt_invalid_token(mock_env):
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_data(b"not-a-valid-token")

def test_store_evidence(mock_env, mock_db_calls):
    mock_create_receipt, mock_save, _ = mock_db_calls
    
    content = b"my sensitive file"
    receipt_id = store_evidence(content, "test.source", "test.target")
    
    assert receipt_id == "R-test-123"
    # Check that create_receipt was called with original content
    mock_create_receipt.assert_called_with(content, "test.source", "test.target")
    
    # Check that save_scan_to_db was called twice
    assert mock_save.call_count == 2
    
    # Check the call for the encrypted blob
    encrypted_call = mock_save.call_args_list[1]
    args, kwargs = encrypted_call
    assert kwargs['module'] == "evidence_vault"
    assert kwargs['scan_id'] == "R-test-123"
    
    # Check that the data saved was actually encrypted
    saved_blob = kwargs['data']['encrypted_blob'].encode('latin-1')
    f = Fernet(os.environ["EVIDENCE_VAULT_KEY"].encode())
    assert f.decrypt(saved_blob) == content

def test_retrieve_evidence(mock_env, mock_db_calls):
    _, mock_save, mock_get = mock_db_calls

    reason = "Unit test access"
    content = retrieve_evidence("R-test-123", reason)
    
    assert content == b"secret data"
    
    # Check that we retrieved the receipt and the blob
    assert mock_get.call_count == 2
    
    # Check that we logged the access event back to the receipt
    assert mock_save.call_count == 1 # Only one save (the updated receipt)
    args, kwargs = mock_save.call_args
    assert kwargs['module'] == "data_custodian"
    assert kwargs['scan_id'] == "R-test-123"
    assert kwargs['data']['chain_of_custody'][-1]['action'] == "ACCESS"
    assert kwargs['data']['chain_of_custody'][-1]['details'] == reason

# --- CLI Tests ---
# We need to mock at the `chimera_intel.cli` level if `grc` is loaded there
# Assuming the GRC plugin loads the `vault_app`

@patch("chimera_intel.core.evidence_vault.store_evidence", return_value="R-cli-stored")
def test_cli_store_evidence(mock_store, mock_env):
    # This test assumes the `grc` command group is correctly loaded in the main `app`
    # We must patch the function that the CLI command calls
    result = runner.invoke(
        app, 
        [
            "grc", "store",
            "--target", "cli-target",
            "--source", "cli-source",
            "--content", "cli secret data"
        ]
    )
    assert result.exit_code == 0
    assert "Evidence securely stored" in result.stdout
    assert "R-cli-stored" in result.stdout
    mock_store.assert_called_with(
        content=b"cli secret data",
        source="cli-source",
        target="cli-target"
    )

@patch("chimera_intel.core.evidence_vault.retrieve_evidence", return_value=b"decrypted cli data")
def test_cli_retrieve_evidence(mock_retrieve, mock_env):
    result = runner.invoke(
        app, 
        [
            "grc", "retrieve",
            "R-cli-123",
            "--reason", "CLI access for test"
        ]
    )
    assert result.exit_code == 0
    assert "Access logged. Decrypted Content:" in result.stdout
    assert "decrypted cli data" in result.stdout
    mock_retrieve.assert_called_with("R-cli-123", "CLI access for test")