import unittest
from unittest.mock import patch, AsyncMock

from chimera_intel.core.deception_detector import analyze_for_deception
from chimera_intel.core.schemas import (
    DeceptionAnalysisResult,
    FootprintResult,
    FootprintData,
    SubdomainReport,
)


class TestDeceptionDetector(unittest.IsolatedAsyncioTestCase):
    """Test cases for the deception_detector module."""

    @patch(
        "chimera_intel.core.deception_detector.gather_footprint_data",
        new_callable=AsyncMock,
    )
    async def test_analyze_for_deception_shared_email(self, mock_gather_footprint):
        """Tests that a link is found between domains with a shared WHOIS email."""
        # Arrange
        # Simulate that the gather_footprint_data function returns different data
        # for different domains, but with the same email.

        async def footprint_side_effect(domain):
            if domain == "company-a.com":
                return FootprintResult(
                    domain=domain,
                    footprint=FootprintData(
                        dns_records={"A": ["1.1.1.1"]},
                        whois_info={"emails": ["contact@shared.com"]},
                        subdomains=SubdomainReport(total_unique=0, results=[]),
                    ),
                )
            if domain == "company-b.com":
                return FootprintResult(
                    domain=domain,
                    footprint=FootprintData(
                        dns_records={"A": ["2.2.2.2"]},
                        whois_info={"emails": ["contact@shared.com"]},
                        subdomains=SubdomainReport(total_unique=0, results=[]),
                    ),
                )
            return FootprintResult(
                domain=domain,
                footprint=FootprintData(
                    dns_records={"A": [domain.replace(".", "") + ".0"]},  # unique ip
                    whois_info={"emails": [f"admin@{domain}"]},
                    subdomains=SubdomainReport(total_unique=0, results=[]),
                ),
            )

        mock_gather_footprint.side_effect = footprint_side_effect

        # We need to simulate the "discovery" of company-b.com from company-a.com's IP.
        # For this test, we'll manually provide it.

        with patch(
            "chimera_intel.core.deception_detector.potential_related_domains",
            {"company-a.com", "company-b.com"},
        ):
            # Act

            result = await analyze_for_deception("company-a.com")
        # Assert

        self.assertIsInstance(result, DeceptionAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.detected_links), 1)
        self.assertEqual(result.detected_links[0].link_type, "Shared Whois Email")
        self.assertEqual(result.detected_links[0].confidence, "High")
        self.assertIn("contact@shared.com", result.detected_links[0].details)


if __name__ == "__main__":
    unittest.main()
