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
    @patch(
        "chimera_intel.core.deception_detector.asyncio.gather", new_callable=AsyncMock
    )
    async def test_analyze_for_deception_shared_email(
        self, mock_asyncio_gather, mock_gather_footprint
    ):
        """Tests that a link is found between domains with a shared WHOIS email."""
        # Arrange
        # The first call to gather_footprint_data is for the initial footprint.

        mock_gather_footprint.return_value = FootprintResult(
            domain="company-a.com",
            footprint=FootprintData(
                whois_info={},
                dns_records={"A": ["1.1.1.1"]},
                subdomains=SubdomainReport(total_unique=0, results=[]),
                ip_threat_intelligence=[],
            ),
        )

        # Mock the return value of asyncio.gather to simulate having found and
        # scanned multiple related domains.

        footprint_a = FootprintResult(
            domain="company-a.com",
            footprint=FootprintData(
                whois_info={"emails": ["contact@shared.com"]},
                dns_records={"A": ["1.1.1.1"]},
                subdomains=SubdomainReport(total_unique=0, results=[]),
                ip_threat_intelligence=[],
            ),
        )
        footprint_b = FootprintResult(
            domain="company-b.com",
            footprint=FootprintData(
                whois_info={"emails": ["contact@shared.com"]},
                dns_records={"A": ["2.2.2.2"]},
                subdomains=SubdomainReport(total_unique=0, results=[]),
                ip_threat_intelligence=[],
            ),
        )
        mock_asyncio_gather.return_value = [footprint_a, footprint_b]

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
