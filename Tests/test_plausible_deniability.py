import pytest
import json
from typer.testing import CliRunner
from chimera_intel.core.plausible_deniability import pd_app, generate_shareable_report, SharingPolicy
from chimera_intel.core.schemas import IntelligenceReport, IntelligenceFinding

runner = CliRunner()

@pytest.fixture
def sample_report():
    """Provides a sample IntelligenceReport object."""
    return IntelligenceReport(
        report_id="test-001",
        title="Secret Report on Project X",
        strategic_summary="This summary mentions Project X and our source 'Alpha'.",
        key_findings=[
            IntelligenceFinding(
                finding_id="f-001",
                description="A critical issue.",
                severity="Critical",
                confidence=0.9,
                source="Alpha"
            ),
            IntelligenceFinding(
                finding_id="f-002",
                description="A medium issue.",
                severity="Medium",
                confidence=0.8,
                source="Beta"
            ),
            IntelligenceFinding(
                finding_id="f-003",
                description="A low issue about Project X.",
                severity="Low",
                confidence=0.95,
                source="Gamma"
            ),
        ],
    )

def test_generate_shareable_report_default_policy(sample_report):
    """Tests the default policy (anonymize and aggregate)."""
    policy = SharingPolicy()
    shareable = generate_shareable_report(sample_report, policy)
    
    # Check anonymization
    assert "Partner-Shared Report" in shareable.title
    assert "(Anonymized Summary)" in shareable.strategic_summary
    
    # Check aggregation
    assert len(shareable.key_findings) == 2 # 1 Critical + 1 Aggregated
    
    critical_finding = next(f for f in shareable.key_findings if f.severity == "Critical")
    aggregated_finding = next(f for f in shareable.key_findings if f.severity == "Medium")
    
    assert critical_finding.finding_id == "f-001"
    assert aggregated_finding.finding_id == "F-AGGREGATED"
    assert "Includes 2 aggregated" in aggregated_finding.description

def test_generate_shareable_report_no_aggregation(sample_report):
    """Tests disabling aggregation."""
    policy = SharingPolicy(aggregate_findings=False)
    shareable = generate_shareable_report(sample_report, policy)
    
    # Should have all 3 original findings
    assert len(shareable.key_findings) == 3
    assert shareable.key_findings[1].finding_id == "f-002"

def test_generate_shareable_report_redaction(sample_report):
    """Tests keyword redaction."""
    policy = SharingPolicy(redact_keywords=["Project X", "Alpha"])
    shareable = generate_shareable_report(sample_report, policy)
    
    assert "[REDACTED]" in shareable.strategic_summary
    assert "source '[REDACTED]'" not in shareable.strategic_summary # It should redact the word
    
    # Check finding redaction
    low_finding = next(f for f in shareable.key_findings if f.finding_id == "F-AGGREGATED")
    # This is tricky because the finding itself was aggregated. Let's test redaction *without* aggregation.
    
    policy_no_agg = SharingPolicy(aggregate_findings=False, redact_keywords=["Project X"])
    shareable_no_agg = generate_shareable_report(sample_report, policy_no_agg)
    
    assert "A low issue about [REDACTED]." in shareable_no_agg.key_findings[2].description

def test_cli_generate(sample_report):
    """Tests the CLI command."""
    with runner.isolated_filesystem():
        # Create dummy input report
        input_path = "report.json"
        output_path = "shareable.json"
        with open(input_path, "w") as f:
            f.write(sample_report.model_dump_json())
            
        result = runner.invoke(
            pd_app, 
            [
                "generate", 
                input_path, 
                "--output", output_path,
                "--redact", "Project X"
            ]
        )
        
        assert result.exit_code == 0
        assert "Shareable report saved" in result.stdout
        
        # Check the output file
        with open(output_path, "r") as f:
            data = json.load(f)
            assert data['strategic_summary'] == "(Anonymized Summary) This summary mentions [REDACTED] and our source 'Alpha'."
            assert len(data['key_findings']) == 2 # Aggregation was on by default