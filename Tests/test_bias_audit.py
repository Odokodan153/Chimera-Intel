import pytest
from typer.testing import CliRunner
import json
from unittest.mock import patch

from chimera_intel.core.bias_audit import bias_audit_app, run_bias_audit
from chimera_intel.core.schemas import BiasAuditResult

runner = CliRunner()


@pytest.fixture
def mock_gemini_client():
    with patch("chimera_intel.core.bias_audit.gemini_client") as mock_client:
        mock_response = {
            "findings": [
                {
                    "bias_type": "Over-reliance on Single Source",
                    "evidence": "Analysis is based only on 'footprint' data.",
                    "recommendation": "Run 'threat_intel' to cross-validate.",
                },
                {
                    "bias_type": "Collection Gap",
                    "evidence": "No information on company leadership.",
                    "recommendation": "Run 'personnel_osint'.",
                },
            ]
        }
        mock_client.generate_response.return_value = json.dumps(mock_response)
        yield mock_client


def test_run_bias_audit(mock_gemini_client):
    """Tests the core logic function."""
    report_data = {
        "target": "example.com",
        "analytical_summary": "example.com is vulnerable.",
        "hypotheses": ["The site will be breached."],
        "results": [
            {"module": "footprint", "data": {"ports": [80, 443]}}
        ]
    }
    
    result = run_bias_audit(report_data, "report.json")

    assert isinstance(result, BiasAuditResult)
    assert not result.error
    assert result.total_findings == 2
    assert result.report_identifier == "report.json"
    assert result.findings[0].bias_type == "Over-reliance on Single Source"
    assert result.findings[1].bias_type == "Collection Gap"


def test_bias_audit_cli(mock_gemini_client, tmp_path):
    """Tests the CLI command."""
    report_data = {
        "target": "example.com",
        "summary": "This is a test summary."
    }
    input_file = tmp_path / "report_to_audit.json"
    input_file.write_text(json.dumps(report_data))

    output_file = tmp_path / "audit_results.json"

    result = runner.invoke(
        bias_audit_app,
        [
            "run",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    
    with open(output_file, "r") as f:
        res_json = json.load(f)
    
    assert res_json["report_identifier"] == str(input_file)
    assert "findings" in res_json
    assert len(res_json["findings"]) == 2
    assert res_json["total_findings"] == 2


def test_bias_audit_cli_no_file(mock_gemini_client):
    """Tests CLI error on missing input file."""
    result = runner.invoke(
        bias_audit_app,
        [
            "run",
            "nonexistentfile.json",
        ],
    )
    assert result.exit_code == 1
    assert "Input file not found" in result.stdout