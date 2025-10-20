import unittest
from unittest.mock import patch, AsyncMock

from chimera_intel.core.deception_detector import analyze_for_deception
from chimera_intel.core.schemas import (
    DeceptionAnalysisResult,
    FootprintResult,
    FootprintData,
    SubdomainReport,
    HistoricalDns,
    TlsCertInfo,
    DnssecInfo,
    BreachInfo,
    WebTechInfo,
    PersonnelInfo,
    KnowledgeGraph,
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
        # Base mock data for a footprint
        mock_footprint_data = FootprintData(
            whois_info={},
            dns_records={"A": ["1.1.1.1"]},
            subdomains=SubdomainReport(total_unique=0, results=[]),
            ip_threat_intelligence=[],
            historical_dns=HistoricalDns(a_records=[], aaaa_records=[], mx_records=[]),
            reverse_ip={},
            asn_info={},
            tls_cert_info=TlsCertInfo(
                issuer="", subject="", sans=[], not_before="", not_after=""
            ),
            dnssec_info=DnssecInfo(
                dnssec_enabled=False, spf_record="", dmarc_record=""
            ),
            ip_geolocation={},
            breach_info=BreachInfo(source="", breaches=[]),
            port_scan_results={},
            web_technologies=WebTechInfo(),
            personnel_info=PersonnelInfo(employees=[]),
            knowledge_graph=KnowledgeGraph(nodes=[], edges=[]),
        )

        # Mock footprint for the initial target, "company-a.com"
        footprint_a = FootprintResult(
            domain="company-a.com",
            footprint=mock_footprint_data.model_copy(
                update={"whois_info": {"emails": ["contact@shared.com"]}}
            ),
        )
        
        # Mock footprint for the related target, "company-b.com"
        footprint_b = FootprintResult(
            domain="company-b.com",
            footprint=mock_footprint_data.model_copy(
                update={
                    "whois_info": {"emails": ["contact@shared.com"]},
                    "dns_records": {"A": ["2.2.2.2"]},
                }
            ),
        )

        # Mock the *first* call to gather_footprint_data (for the initial_footprint)
        mock_gather_footprint.return_value = footprint_a

        # Mock the two separate calls to asyncio.gather
        mock_asyncio_gather.side_effect = [
            # 1. Return for reverse_ip_tasks: a list of lists of domain strings
            [["company-b.com"]],
            
            # 2. Return for footprint tasks: a list of FootprintResult objects
            [footprint_b]
        ]

        # Act
        result = await analyze_for_deception("company-a.com")

        # Assert
        self.assertIsInstance(result, DeceptionAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.detected_links), 1)
        self.assertEqual(result.detected_links[0].link_type, "Shared Whois Email")
        self.assertEqual(result.detected_links[0].confidence, "High")
        self.assertIn("contact@shared.com", result.detected_links[0].details)
        
        # Check that the entities are correct (order might vary)
        entities = {
            result.detected_links[0].entity_a,
            result.detected_links[0].entity_b,
        }
        self.assertIn("company-a.com", entities)
        self.assertIn("company-b.com", entities)


if __name__ == "__main__":
    unittest.main()