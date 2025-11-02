import pytest
from typer.testing import CliRunner
import json
from unittest.mock import patch

from chimera_intel.core.privacy_impact_reporter import privacy_impact_reporter_app
from chimera_intel.core.ethical_guardrails import EthicalGuardrails # We need to mock this

runner = CliRunner()


@pytest.fixture
def mock_guardrail():
    """Mocks the EthicalGuardrails class."""
    with patch(
        "chimera_intel.core.privacy_impact_reporter.EthicalGuardrails"
    ) as mock_class:
        mock_instance = mock_class.return_value
        
        # Define side effect for PII check
        mock_instance.check_content_for_pii.side_effect = [
            None,  # First doc is clean
            {"EMAIL": "test@...com", "PHONE": "555-..."} # Second doc has PII
        ]
        yield mock_instance


@patch("chimera_intel.core.privacy_impact_reporter.save_scan_to_db")
@patch("chimera_intel.core.privacy_impact_reporter.resolve_target", lambda x, **kwargs: x or "default")
def test_privacy_report_cli(mock_save, mock_guardrail, tmp_path):
    """Tests the CLI command for generating a privacy report."""
    documents = [
        {"content": "This document is clean and safe."},
        {"content": "This one has PII: test@example.com and 555-123-4567."}
    ]
    input_file = tmp_path / "inputs.json"
    input_file.write_text(json.dumps(documents))

    output_file = tmp_path / "results.json"

    result = runner.invoke(
        privacy_impact_reporter_app,
        [
            "run",
            "PIITest",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    
    with open(output_file, "r") as f:
        res_json = json.load(f)
    
    assert res_json["target"] == "PIITest"
    assert res_json["total_documents_scanned"] == 2
    assert res_json["documents_with_pii"] == 1
    assert res_json["overall_risk_level"] == "High" # 1/2 = 50% > 10%
    assert res_json["violation_summary"]["EMAIL"] == 1
    assert res_json["violation_summary"]["PHONE"] == 1
    assert "Do not use data until fully anonymized" in res_json["mitigation_steps"]