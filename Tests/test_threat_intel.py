import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response
from chimera_intel.core.threat_intel import get_threat_intel_otx
from chimera_intel.core.schemas import ThreatIntelResult


class TestThreatIntel(unittest.TestCase):
    """Test cases for the threat_intel module."""

    @patch("chimera_intel.core.threat_intel.API_KEYS")
    @patch("chimera_intel.core.threat_intel.async_client.get", new_callable=AsyncMock)
    def test_get_threat_intel_otx_malicious_ip(self, mock_get, mock_api_keys):
        """Tests a successful OTX lookup for a malicious IP."""
        mock_api_keys.otx_api_key = "fake_otx_key"
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {
                        "name": "Bad IP Pulse",
                        "malware_families": ["zbot"],
                        "tags": ["malicious"],
                    }
                ],
            }
        }
        mock_get.return_value = mock_response

        result = asyncio.run(get_threat_intel_otx("8.8.8.8"))

        self.assertIsInstance(result, ThreatIntelResult)
        self.assertTrue(result.is_malicious)
        self.assertEqual(result.pulse_count, 1)
        self.assertEqual(len(result.pulses), 1)
        self.assertEqual(result.pulses[0].name, "Bad IP Pulse")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.threat_intel.API_KEYS")
    @patch("chimera_intel.core.threat_intel.async_client.get", new_callable=AsyncMock)
    def test_get_threat_intel_otx_clean_domain(self, mock_get, mock_api_keys):
        """Tests a successful OTX lookup for a clean (unknown) domain."""
        mock_api_keys.otx_api_key = "fake_otx_key"
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 404  # OTX returns 404 for unknown indicators
        mock_get.return_value = mock_response

        result = asyncio.run(get_threat_intel_otx("google.com"))

        self.assertIsInstance(result, ThreatIntelResult)
        self.assertFalse(result.is_malicious)
        self.assertEqual(result.pulse_count, 0)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.threat_intel.API_KEYS")
    def test_get_threat_intel_no_api_key(self, mock_api_keys):
        """Tests that the function returns None if no API key is set."""
        mock_api_keys.otx_api_key = None
        result = asyncio.run(get_threat_intel_otx("google.com"))
        self.assertIsNone(result)

    @patch("chimera_intel.core.threat_intel.API_KEYS")
    @patch("chimera_intel.core.threat_intel.async_client.get", new_callable=AsyncMock)
    def test_get_threat_intel_api_error(self, mock_get, mock_api_keys):
        """Tests the function's behavior during an API error."""
        mock_api_keys.otx_api_key = "fake_otx_key"
        mock_get.side_effect = Exception("API is down")

        result = asyncio.run(get_threat_intel_otx("8.8.8.8"))
        self.assertIsInstance(result, ThreatIntelResult)
        self.assertIsNotNone(result.error)
        self.assertIn("API is down", result.error)


if __name__ == "__main__":
    unittest.main()
