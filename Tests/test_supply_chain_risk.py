import unittest
from unittest.mock import patch, MagicMock, call
from httpx import Response, RequestError

from chimera_intel.core.supply_chain_risk import analyze_supply_chain_risk
from chimera_intel.core.schemas import SoftwareComponent, SupplyChainRiskResult


class TestSupplyChainRisk(unittest.TestCase):
    """Test cases for the Supply Chain Risk AI module."""

    @patch("chimera_intel.core.supply_chain_risk.sync_client.get")
    def test_analyze_supply_chain_success_vulns_found(self, mock_get):
        """Tests successful analysis with vulnerabilities found."""
        # --- Arrange ---
        components = [
            SoftwareComponent(name="requests", version="2.28.0"),
            SoftwareComponent(name="numpy", version="1.23.0"),
        ]

        # Mock API response for 'requests'
        mock_response_requests = MagicMock(spec=Response)
        mock_response_requests.raise_for_status.return_value = None
        mock_response_requests.json.return_value = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2023-1234",
                    "severity": "HIGH",
                    "description": "A high severity vulnerability.",
                }
            ]
        }
        
        # Mock API response for 'numpy' (clean)
        mock_response_numpy = MagicMock(spec=Response)
        mock_response_numpy.raise_for_status.return_value = None
        mock_response_numpy.json.return_value = {"vulnerabilities": []}
        
        mock_get.side_effect = [mock_response_requests, mock_response_numpy]

        # --- Act ---
        with patch("chimera_intel.core.supply_chain_risk.API_KEYS.vuln_db_api_key", "fake_key"):
            result = analyze_supply_chain_risk(components)

        # --- Assert ---
        self.assertIsInstance(result, SupplyChainRiskResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.found_vulnerabilities), 1)
        self.assertEqual(result.found_vulnerabilities[0].cve_id, "CVE-2023-1234")
        self.assertEqual(result.found_vulnerabilities[0].component_name, "requests")
        self.assertEqual(result.risk_score, 3.5) # (7 + 0) / 2 = 3.5
        self.assertIn("Found 1 vulnerabilities", result.summary)

    @patch("chimera_intel.core.supply_chain_risk.sync_client.get")
    def test_analyze_supply_chain_no_vulns(self, mock_get):
        """Tests successful analysis with no vulnerabilities found."""
        # --- Arrange ---
        components = [SoftwareComponent(name="clean-package", version="1.0.0")]

        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        # --- Act ---
        with patch("chimera_intel.core.supply_chain_risk.API_KEYS.vuln_db_api_key", "fake_key"):
            result = analyze_supply_chain_risk(components)

        # --- Assert ---
        self.assertIsInstance(result, SupplyChainRiskResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.found_vulnerabilities), 0)
        self.assertEqual(result.risk_score, 0.0)
        self.assertIn("Found 0 vulnerabilities", result.summary)

    def test_analyze_no_api_key(self):
        """Tests error handling when no API key is set."""
        components = [SoftwareComponent(name="requests", version="2.28.0")]
        
        with patch("chimera_intel.core.supply_chain_risk.API_KEYS.vuln_db_api_key", None):
            result = analyze_supply_chain_risk(components)
            
        self.assertIsInstance(result, SupplyChainRiskResult)
        self.assertIsNone(result.summary)
        self.assertIn("VULN_DB_API_KEY) is not configured", result.error)

    @patch("chimera_intel.core.supply_chain_risk.sync_client.get")
    def test_analyze_api_error(self, mock_get):
        """Tests error handling during an API failure."""
        components = [SoftwareComponent(name="requests", version="2.28.0")]
        mock_get.side_effect = RequestError("Connection failed")
        
        with patch("chimera_intel.core.supply_chain_risk.API_KEYS.vuln_db_api_key", "fake_key"):
            result = analyze_supply_chain_risk(components)
            
        self.assertIsInstance(result, SupplyChainRiskResult)
        self.assertIn("An API error occurred", result.error)


if __name__ == "__main__":
    unittest.main()