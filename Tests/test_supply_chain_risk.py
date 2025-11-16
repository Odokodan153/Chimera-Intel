import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError

from chimera_intel.core.supply_chain_risk import (
    analyze_supply_chain_risk, 
    _get_severity_from_osv
)
from chimera_intel.core.schemas import SoftwareComponent, SupplyChainRiskResult


class TestSupplyChainRisk(unittest.TestCase):
    """Test cases for the Supply Chain Risk AI module (using OSV.dev API)."""

    @patch("chimera_intel.core.supply_chain_risk.sync_client.post")
    def test_analyze_supply_chain_success_vulns_found(self, mock_post):
        """Tests successful analysis with vulnerabilities found."""
        # --- Arrange ---
        components = [
            SoftwareComponent(name="requests", version="2.28.0"),
            SoftwareComponent(name="numpy", version="1.23.0"),
        ]

        # Mock the single batch API response from OSV.dev
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [
                {
                    # Result for "requests"
                    "vulns": [
                        {
                            "id": "CVE-2023-1234",
                            "summary": "A high severity vulnerability.",
                            "severity": [{"type": "CVSS_V3", "score": "7.5"}] # 7.5 = HIGH
                        }
                    ]
                },
                {
                    # Result for "numpy" (clean)
                    "vulns": []
                }
            ]
        }
        mock_post.return_value = mock_response

        # --- Act ---
        result = analyze_supply_chain_risk(components)

        # --- Assert ---
        # Check that the POST call was made correctly
        expected_json_payload = {
            "queries": [
                {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.28.0"},
                {"package": {"name": "numpy", "ecosystem": "PyPI"}, "version": "1.23.0"}
            ]
        }
        mock_post.assert_called_once_with(
            "https://api.osv.dev/v1/querybatch", 
            json=expected_json_payload
        )

        self.assertIsInstance(result, SupplyChainRiskResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.found_vulnerabilities), 1)
        self.assertEqual(result.found_vulnerabilities[0].cve_id, "CVE-2023-1234")
        self.assertEqual(result.found_vulnerabilities[0].component_name, "requests")
        self.assertEqual(result.found_vulnerabilities[0].severity, "HIGH")
        self.assertEqual(result.risk_score, 3.5) # (7 [HIGH] + 0 [CLEAN]) / 2 = 3.5
        self.assertIn("Found 1 vulnerabilities", result.summary)

    @patch("chimera_intel.core.supply_chain_risk.sync_client.post")
    def test_analyze_supply_chain_no_vulns(self, mock_post):
        """Tests successful analysis with no vulnerabilities found."""
        # --- Arrange ---
        components = [SoftwareComponent(name="clean-package", version="1.0.0")]

        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": []
                }
            ]
        }
        mock_post.return_value = mock_response

        # --- Act ---
        result = analyze_supply_chain_risk(components)

        # --- Assert ---
        self.assertIsInstance(result, SupplyChainRiskResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.found_vulnerabilities), 0)
        self.assertEqual(result.risk_score, 0.0)
        self.assertIn("Found 0 vulnerabilities", result.summary)

    @patch("chimera_intel.core.supply_chain_risk.sync_client.post")
    def test_analyze_api_error(self, mock_post):
        """Tests error handling during an API failure."""
        components = [SoftwareComponent(name="requests", version="2.28.0")]
        mock_post.side_effect = RequestError("Connection failed")
        
        result = analyze_supply_chain_risk(components)
            
        self.assertIsInstance(result, SupplyChainRiskResult)
        self.assertIn("An API error occurred", result.error)

    # --- Tests for the helper function ---
    
    def test_severity_helper_mappings(self):
        """Tests the CVSS score to severity string mapping."""
        self.assertEqual(
            _get_severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "9.1"}]}), 
            "CRITICAL"
        )
        self.assertEqual(
            _get_severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "7.0"}]}), 
            "HIGH"
        )
        self.assertEqual(
            _get_severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "4.5"}]}), 
            "MEDIUM"
        )
        self.assertEqual(
            _get_severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "0.1"}]}), 
            "LOW"
        )
        self.assertEqual(
            _get_severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "0.0"}]}), 
            "UNKNOWN" # 0.0 is typically "NONE", we map to UNKNOWN
        )

    def test_severity_helper_edge_cases(self):
        """Tests edge cases for the severity helper."""
        # No severity field
        self.assertEqual(_get_severity_from_osv({}), "UNKNOWN")
        # Empty severity list
        self.assertEqual(_get_severity_from_osv({"severity": []}), "UNKNOWN")
        # Non-CVSS_V3 type
        self.assertEqual(
            _get_severity_from_osv({"severity": [{"type": "CVSS_V2", "score": "9.0"}]}), 
            "UNKNOWN"
        )
        # CVSS_V3 score is a vector string (which our simple parser skips)
        self.assertEqual(
            _get_severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/..."}]}), 
            "UNKNOWN"
        )
        # Multiple scores, should pick the highest CVSS_V3
        self.assertEqual(
            _get_severity_from_osv({"severity": [
                {"type": "CVSS_V2", "score": "10.0"},
                {"type": "CVSS_V3", "score": "5.0"}, # MEDIUM
                {"type": "CVSS_V3", "score": "7.2"}  # HIGH
            ]}), 
            "HIGH"
        )


if __name__ == "__main__":
    unittest.main()