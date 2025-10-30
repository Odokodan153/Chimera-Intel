import unittest
import os
from chimera_intel.core.dissemination_suite import (
    generate_executive_briefing,
    generate_technical_report,
    generate_tactical_alert,
)
from chimera_intel.core.schemas import IntelligenceReport, IntelligenceFinding


class TestDisseminationSuite(unittest.TestCase):
    """Test cases for the Automated Dissemination & Briefing Suite."""

    def setUp(self):
        """Set up a sample intelligence report for testing."""
        self.report = IntelligenceReport(
            report_id="test-001",
            title="Test Report",
            strategic_summary="This is a test summary.",
            key_findings=[
                IntelligenceFinding(
                    finding_id="f-001",
                    description="A critical issue.",
                    severity="Critical",
                    confidence=0.9,
                ),
                IntelligenceFinding(
                    finding_id="f-002",
                    description="A minor issue.",
                    severity="Low",
                    confidence=0.95,
                ),
            ],
        )

    def test_generate_executive_briefing(self):
        """Tests the generation of a PDF executive briefing."""
        output_path = "test_briefing.pdf"
        success = generate_executive_briefing(self.report, output_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))
        os.remove(output_path)

    def test_generate_technical_report(self):
        """Tests the generation of a detailed technical report."""
        tech_report = generate_technical_report(self.report)
        self.assertIn("strategic_summary", tech_report)
        self.assertIn("key_findings", tech_report)

    def test_generate_tactical_alert(self):
        """Tests the generation of a tactical alert."""
        alert = generate_tactical_alert(self.report)
        self.assertIsNotNone(alert)
        self.assertIn("CRITICAL ALERT", alert)

    def test_no_tactical_alert_if_not_critical(self):
        """Tests that no alert is generated if there are no critical findings."""
        report_no_critical = IntelligenceReport(
            report_id="test-002",
            title="No Critical Issues",
            strategic_summary="All clear.",
            key_findings=[
                IntelligenceFinding(
                    finding_id="f-003",
                    description="A medium issue.",
                    severity="Medium",
                    confidence=0.8,
                )
            ],
        )
        alert = generate_tactical_alert(report_no_critical)
        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
