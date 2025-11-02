import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError

from chimera_intel.core.zero_day_tracking import monitor_emerging_exploits
from chimera_intel.core.schemas import ZeroDayTrackingResult


class TestZeroDayTracking(unittest.TestCase):
    """Test cases for the Zero-Day Tracking module."""

    @patch("chimera_intel.core.zero_day_tracking.sync_client.get")
    def test_monitor_exploits_found(self, mock_get):
        """Tests successfully finding emerging exploits."""
        # --- Arrange ---
        query = "Microsoft Exchange"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "exploits": [
                {
                    "id": "CVE-2023-9999",
                    "product": "Exchange Server",
                    "vendor": "Microsoft",
                    "description": "Remote Code Execution vulnerability.",
                    "source_url": "https://example.com/cve-2023-9999",
                    "discovered_on": "2023-10-27T10:00:00Z",
                    "is_zero_day": True,
                }
            ]
        }
        mock_get.return_value = mock_response

        # --- Act ---
        with patch("chimera_intel.core.zero_day_tracking.API_KEYS.exploit_feed_api_key", "fake_key"):
            result = monitor_emerging_exploits(query)

        # --- Assert ---
        self.assertIsInstance(result, ZeroDayTrackingResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.query, query)
        self.assertEqual(len(result.emerging_exploits), 1)
        self.assertEqual(result.emerging_exploits[0].exploit_id, "CVE-2023-9999")
        self.assertTrue(result.emerging_exploits[0].is_zero_day)
        self.assertIn("Found 1 emerging exploits", result.summary)

    @patch("chimera_intel.core.zero_day_tracking.sync_client.get")
    def test_monitor_no_exploits_found(self, mock_get):
        """Tests the response when no exploits match the query."""
        # --- Arrange ---
        query = "ObscureProduct"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"exploits": []}
        mock_get.return_value = mock_response

        # --- Act ---
        with patch("chimera_intel.core.zero_day_tracking.API_KEYS.exploit_feed_api_key", "fake_key"):
            result = monitor_emerging_exploits(query)

        # --- Assert ---
        self.assertIsInstance(result, ZeroDayTrackingResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.emerging_exploits), 0)
        self.assertIn("No emerging exploits found", result.summary)

    def test_monitor_no_api_key(self):
        """Tests that the function returns an error if the API key is not set."""
        with patch("chimera_intel.core.zero_day_tracking.API_KEYS.exploit_feed_api_key", None):
            result = monitor_emerging_exploits("query")
            
        self.assertIsInstance(result, ZeroDayTrackingResult)
        self.assertIsNotNone(result.error)
        self.assertIn("EXPLOIT_FEED_API_KEY) is not configured", result.error)

    @patch("chimera_intel.core.zero_day_tracking.sync_client.get")
    def test_monitor_api_error(self, mock_get):
        """Tests error handling during an API failure."""
        mock_get.side_effect = RequestError("Feed unreachable")
        
        with patch("chimera_intel.core.zero_day_tracking.API_KEYS.exploit_feed_api_key", "fake_key"):
            result = monitor_emerging_exploits("query")
            
        self.assertIsInstance(result, ZeroDayTrackingResult)
        self.assertIn("An API error occurred", result.error)

if __name__ == "__main__":
    unittest.main()