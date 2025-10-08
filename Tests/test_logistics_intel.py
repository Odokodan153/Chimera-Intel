import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from chimera_intel.core.logistics_intel import track_shipment, ShipmentDetails


class TestLogisticsIntel(unittest.TestCase):
    """Test cases for the logistics_intel module."""

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    @patch(
        "chimera_intel.core.logistics_intel.httpx.AsyncClient.post",
        new_callable=AsyncMock,
    )
    async def test_track_shipment_success(self, mock_post, mock_api_keys):
        """Tests a successful shipment tracking call."""
        mock_api_keys.easypost_api_key = "fake_key"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "tracking_code": "EZ123456789",
            "carrier": "USPS",
            "status": "in_transit",
            "tracking_details": [
                {
                    "status": "in_transit",
                    "message": "On its way",
                    "datetime": "2025-01-01T12:00:00Z",
                }
            ],
        }
        mock_post.return_value = mock_response

        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsInstance(result, ShipmentDetails)
        self.assertEqual(result.status, "in_transit")
        self.assertEqual(len(result.updates), 1)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    async def test_track_shipment_no_api_key(self, mock_api_keys):
        """Tests the function when the API key is not set."""
        mock_api_keys.easypost_api_key = None
        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsNotNone(result.error)
        self.assertIn("API key is not configured", result.error)


if __name__ == "__main__":
    unittest.main()
