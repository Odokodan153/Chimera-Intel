import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import hashlib

from chimera_intel.core.media_governance import (
    governance_app,
    log_consent_form,
    request_media_approval,
    set_media_approval_status,
    MediaAssetStatus
)
from chimera_intel.core.schemas import ConsentRecord

runner = CliRunner()

@pytest.fixture
def mock_db_calls():
    """Mock all database and vault calls."""
    with patch("chimera_intel.core.media_governance.store_evidence") as mock_store, \
         patch("chimera_intel.core.media_governance.save_scan_to_db") as mock_save, \
         patch("chimera_intel.core.media_governance.get_scan_from_db") as mock_get:
        
        mock_store.return_value = "vault-receipt-123"
        
        mock_receipt_data = {
            "scan_id": "R-test-123",
            "target": "test-target",
            "module": "data_custodian",
            "data": {"chain_of_custody": []}
        }
        mock_get.return_value = mock_receipt_data
        
        yield mock_store, mock_save, mock_get, mock_receipt_data

# --- Unit Tests ---

def test_log_consent_form(mock_db_calls):
    mock_store, mock_save, _, _ = mock_db_calls
    
    file_content = b"This is a signed PDF"
    file_hash = hashlib.sha256(file_content).hexdigest()
    
    consent_id = log_consent_form(
        person_name="John Doe",
        file_content=file_content,
        details="Test consent",
        contact_info="john@example.com"
    )
    
    # 1. Check that the file was stored in the vault
    mock_store.assert_called_with(
        content=file_content,
        source="consent_uploader",
        target="John Doe"
    )
    
    # 2. Check that the consent record was saved to the DB
    assert mock_save.call_count == 1
    args, kwargs = mock_save.call_args
    
    assert kwargs['module'] == "consent_log"
    assert kwargs['scan_id'] == consent_id
    assert kwargs['data']['person_name'] == "John Doe"
    assert kwargs['data']['consent_form_sha256'] == file_hash
    assert kwargs['data']['consent_form_storage_id'] == "vault-receipt-123"

def test_request_media_approval(mock_db_calls):
    _, mock_save, mock_get, mock_receipt = mock_db_calls
    
    requestor = "user@chimera.corp"
    reason = "Ready for review"
    
    request_media_approval("R-test-123", requestor, reason)
    
    # Check it fetched the right receipt
    mock_get.assert_called_with("R-test-123", module_name="data_custodian")
    
    # Check it saved the updated receipt
    assert mock_save.call_count == 1
    args, kwargs = mock_save.call_args
    
    assert kwargs['module'] == "data_custodian"
    assert kwargs['scan_id'] == "R-test-123"
    
    # Check the chain of custody
    coc = kwargs['data']['chain_of_custody']
    assert len(coc) == 1
    assert coc[0]['action'] == MediaAssetStatus.PENDING_REVIEW.value
    assert coc[0]['actor'] == requestor
    assert coc[0]['details'] == reason

def test_set_media_approval_status(mock_db_calls):
    _, mock_save, mock_get, _ = mock_db_calls
    
    approver = "manager@chimera.corp"
    notes = "Looks good"
    
    set_media_approval_status(
        "R-test-123",
        approver,
        MediaAssetStatus.APPROVED,
        notes
    )
    
    # Check it saved the updated receipt
    assert mock_save.call_count == 1
    args, kwargs = mock_save.call_args
    
    # Check the chain of custody
    coc = kwargs['data']['chain_of_custody']
    assert len(coc) == 1
    assert coc[0]['action'] == MediaAssetStatus.APPROVED.value
    assert coc[0]['actor'] == approver
    assert coc[0]['details'] == notes

# --- CLI Tests ---

@patch("chimera_intel.core.media_governance.log_consent_form", return_value="consent-cli-123")
def test_cli_log_consent(mock_log_consent):
    with open("dummy_consent.pdf", "wb") as f:
        f.write(b"dummy pdf content")
    
    result = runner.invoke(
        governance_app,
        [
            "log-consent",
            "--name", "Jane Doe (CLI)",
            "--form", "dummy_consent.pdf",
            "--details", "CLI Test"
        ]
    )
    
    assert result.exit_code == 0
    assert "Consent form successfully logged" in result.stdout
    assert "consent-cli-123" in result.stdout
    
    # Check that the mock was called with the file content
    mock_log_consent.assert_called_once()
    assert mock_log_consent.call_args[1]['file_content'] == b"dummy pdf content"
    
    import os
    os.remove("dummy_consent.pdf")

@patch("chimera_intel.core.media_governance.request_media_approval")
def test_cli_request_approval(mock_request):
    result = runner.invoke(
        governance_app,
        [
            "request-approval",
            "R-cli-456",
            "--by", "cli.user@test.com"
        ]
    )
    
    assert result.exit_code == 0
    assert "Successfully requested approval" in result.stdout
    mock_request.assert_called_with("R-cli-456", "cli.user@test.com", "Please review for publication.")

@patch("chimera_intel.core.media_governance.set_media_approval_status")
def test_cli_approve(mock_set_status):
    result = runner.invoke(
        governance_app,
        [
            "approve",
            "R-cli-789",
            "--by", "cli.manager@test.com"
        ]
    )
    
    assert result.exit_code == 0
    assert "has been APPROVED" in result.stdout
    mock_set_status.assert_called_with(
        receipt_id="R-cli-789",
        approver="cli.manager@test.com",
        status=MediaAssetStatus.APPROVED,
        notes="Approved for external release."
    )

@patch("chimera_intel.core.media_governance.set_media_approval_status")
def test_cli_reject(mock_set_status):
    result = runner.invoke(
        governance_app,
        [
            "reject",
            "R-cli-101",
            "--by", "cli.manager@test.com",
            "--reason", "Image is watermarked"
        ]
    )
    
    assert result.exit_code == 0
    assert "has been REJECTED" in result.stdout
    mock_set_status.assert_called_with(
        receipt_id="R-cli-101",
        approver="cli.manager@test.com",
        status=MediaAssetStatus.REJECTED,
        notes="Image is watermarked"
    )