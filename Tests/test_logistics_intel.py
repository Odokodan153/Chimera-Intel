import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from chimera_intel.core.logistics_intel import (
    track_shipment,
    ShipmentDetails,
    TrackingUpdate
)
from chimera_intel.core.logistics_intel import app as cli_app
import httpx
from typer.testing import CliRunner

class TestLogisticsIntel(unittest.IsolatedAsyncioTestCase):
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
            "est_delivery_date": "2025-01-05T12:00:00Z",
            "tracking_details": [
                {
                    "status": "in_transit",
                    "message": "On its way",
                    "datetime": "2025-01-01T12:00:00Z",
                }
            ],
        }
        mock_post.return_value = mock_response
        mock_response.raise_for_status = MagicMock() # Ensure raise_for_status does nothing

        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsInstance(result, ShipmentDetails)
        self.assertEqual(result.status, "in_transit")
        self.assertEqual(result.estimated_delivery_date, "2025-01-05T12:00:00Z")
        self.assertEqual(len(result.updates), 1)
        self.assertEqual(result.updates[0].message, "On its way")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    async def test_track_shipment_no_api_key(self, mock_api_keys):
        """Tests the function when the API key is not set."""
        mock_api_keys.easypost_api_key = None
        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsNotNone(result.error)
        self.assertIn("API key is not configured", result.error)

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    @patch(
        "chimera_intel.core.logistics_intel.httpx.AsyncClient.post",
        new_callable=AsyncMock,
    )
    async def test_track_shipment_api_http_error(self, mock_post, mock_api_keys):
        """Tests the function when the API returns an HTTP error."""
        mock_api_keys.easypost_api_key = "fake_key"
        
        # Mock the response within the exception
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.text = '{"error": "Invalid API key"}'
        
        mock_post.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized",
            request=MagicMock(),
            response=mock_response,
        )

        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsNotNone(result.error)
        self.assertIn("API error", result.error)
        self.assertIn("Invalid API key", result.error)

    @patch("chimera_intel.core.logistics_intel.API_KEYS")
    @patch(
        "chimera_intel.core.logistics_intel.httpx.AsyncClient.post",
        new_callable=AsyncMock,
    )
    async def test_track_shipment_general_exception(self, mock_post, mock_api_keys):
        """Tests the function during a general exception."""
        mock_api_keys.easypost_api_key = "fake_key"
        mock_post.side_effect = Exception("A general error")

        result = await track_shipment("EZ123456789", "USPS")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error, "A general error")

    # --- CLI Tests ---

    def setUp(self):
        self.runner = CliRunner()

    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_track_success(self, mock_asyncio_run):
        """Tests the CLI track command for a successful lookup."""
        mock_updates = [
            TrackingUpdate(
                status="pre_transit",
                message="Label created",
                timestamp="2025-01-01T10:00:00Z",
            )
        ]
        mock_result = ShipmentDetails(
            tracking_code="EZ123",
            carrier="USPS",
            status="pre_transit",
            estimated_delivery_date="2025-01-05",
            updates=mock_updates,
            error=None,
        )
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(cli_app, ["track", "EZ123", "--carrier", "USPS"])
        
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Status for EZ123 (USPS): pre_transit", result.stdout)
        self.assertIn("Estimated Delivery: 2025-01-05", result.stdout)
        self.assertIn("Tracking History", result.stdout)
        self.assertIn("Label created", result.stdout)

    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_track_success_no_delivery_date(self, mock_asyncio_run):
        """Tests the CLI track command when no estimated delivery date is available."""
        mock_result = ShipmentDetails(
            tracking_code="EZ123",
            carrier="USPS",
            status="in_transit",
            estimated_delivery_date=None, # No date
            updates=[],
            error=None,
        )
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(cli_app, ["track", "EZ123", "--carrier", "USPS"])
        
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Status for EZ123 (USPS): in_transit", result.stdout)
        self.assertNotIn("Estimated Delivery:", result.stdout) # Verify it doesn't print this line

    @patch("chimera_intel.core.logistics_intel.asyncio.run")
    def test_cli_track_error(self, mock_asyncio_run):
        """Tests the CLI track command when an error occurs."""
        mock_result = ShipmentDetails(
            tracking_code="EZ123",
            carrier="USPS",
            status="Error",
            updates=[],
            error="No API key",
        )
        mock_asyncio_run.return_value = mock_result

        result = self.runner.invoke(cli_app, ["track", "EZ123", "--carrier", "USPS"])
        
        self.assertEqual(result.exit_code, 0) # CLI exits 0
        self.assertIn("Error:", result.stdout)
        self.assertIn("No API key", result.stdout)
        self.assertNotIn("Tracking History", result.stdout) # Table should not be printed

    def test_cli_track_missing_carrier(self):
        """Tests the CLI when the required --carrier option is missing."""
        result = self.runner.invoke(cli_app, ["track", "EZ123"])
        self.assertNotEqual(result.exit_code, 0) # Fails due to missing option
        self.assertIn("Missing option '--carrier'", result.stdout)


if __name__ == "__main__":
    unittest.main()