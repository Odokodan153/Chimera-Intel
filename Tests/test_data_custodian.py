import pytest
from typer.testing import CliRunner
from unittest.mock import patch
import json

from chimera_intel.core.data_custodian import data_custodian_app, create_data_receipt

runner = CliRunner()


@patch("chimera_intel.core.data_custodian.save_scan_to_db")
def test_create_data_receipt_logic(mock_save):
    """Tests the core logic of receipt creation."""
    content = b"This is test data"
    source = "test.com"
    target = "TestTarget"
    
    receipt = create_data_receipt(content, source, target)
    
    assert receipt.target == target
    assert receipt.source == source
    assert receipt.content_sha256 == "41801c30573934d6560195a60a76b97017721a311181580665393f666b86c3f1"
    assert receipt.judicial_hold is False
    assert len(receipt.chain_of_custody) == 1
    assert receipt.chain_of_custody[0].action == "INGEST"


@patch("chimera_intel.core.data_custodian.save_scan_to_db")
@patch("chimera_intel.core.data_custodian.resolve_target", lambda x, **kwargs: x or "default")
def test_data_custodian_cli_timestamp(mock_save):
    """Tests the 'timestamp' CLI command."""
    result = runner.invoke(
        data_custodian_app,
        [
            "timestamp",
            "CLITarget",
            "--content",
            "My secret data",
            "--source",
            "source.org",
        ],
    )
    assert result.exit_code == 0
    assert "Receipt created:" in result.stdout
    assert '"target": "CLITarget"' in result.stdout
    assert '"source": "source.org"' in result.stdout


@patch("chimera_intel.core.data_custodian.set_judicial_hold")
def test_data_custodian_cli_hold(mock_set_hold):
    """Tests the 'hold' CLI command."""
    mock_set_hold.return_value = {"receipt_id": "R-123", "status": "Judicial hold set to True"}
    
    result = runner.invoke(
        data_custodian_app,
        ["hold", "R-123", "--reason", "Legal Case 456"],
    )
    assert result.exit_code == 0
    assert '"status": "Judicial hold set to True"' in result.stdout
    
    # Test release
    mock_set_hold.return_value = {"receipt_id": "R-123", "status": "Judicial hold set to False"}
    result = runner.invoke(
        data_custodian_app,
        ["hold", "R-123", "--reason", "Case Closed", "--release"],
    )
    assert result.exit_code == 0
    assert '"status": "Judicial hold set to False"' in result.stdout