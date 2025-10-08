import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.risk_assessment import (
    calculate_risk,
    assess_risk_from_indicator,
)
from chimera_intel.core.schemas import (
    RiskAssessmentResult,
    ThreatIntelResult,
    PulseInfo,
    Vulnerability,
    ThreatActor,
)


class TestRiskAssessment(unittest.TestCase):
    """Test cases for the risk_assessment module."""

    def test_calculate_risk_with_vulnerabilities(self):
        """Tests risk calculation with vulnerabilities."""
        vulnerabilities = [Vulnerability(cve="CVE-2021-44228", severity="Critical")]
        result = calculate_risk(
            asset="WebServer",
            threat="Remote Code Execution",
            probability=0.7,
            impact=8.0,
            vulnerabilities=vulnerabilities,
        )
        self.assertEqual(result.risk_level, "Critical")
        self.assertIn("Patch identified vulnerabilities.", result.mitigation)

    @patch(
        "chimera_intel.core.risk_assessment.get_threat_intel_otx",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.risk_assessment.search_vulnerabilities",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.risk_assessment.search_threat_actors",
        new_callable=AsyncMock,
    )
    async def test_assess_risk_from_indicator_comprehensive(
        self, mock_search_actors, mock_search_vulns, mock_get_intel
    ):
        """Tests a comprehensive risk assessment from an indicator."""
        mock_get_intel.return_value = ThreatIntelResult(
            indicator="1.2.3.4",
            is_malicious=True,
            pulse_count=60,
            pulses=[PulseInfo(name="APT Pulse", tags=["apt"], malware_families=[])],
        )
        mock_search_vulns.return_value = [
            Vulnerability(cve="CVE-2022-12345", severity="High")
        ]
        mock_search_actors.return_value = [ThreatActor(name="APT28", ttps=["Phishing"])]

        result = await assess_risk_from_indicator("1.2.3.4", service="apache")
        self.assertEqual(result.risk_level, "Critical")
        self.assertIn("Patch identified vulnerabilities.", result.mitigation)
        self.assertIn(
            "Monitor for TTPs associated with identified threat actors.",
            result.mitigation,
        )


if __name__ == "__main__":
    unittest.main()
