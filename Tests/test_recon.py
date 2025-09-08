import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.recon import (
    find_credential_leaks,
    find_digital_assets,
    analyze_threat_infrastructure,
)
from chimera_intel.core.schemas import (
    CompromisedCredential,
    MobileApp,
    RelatedIndicator,
)


class TestRecon(unittest.TestCase):
    """Test cases for the advanced reconnaissance module."""

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.sync_client.get")
    def test_find_credential_leaks_success(self, mock_get, mock_api_keys):
        """Tests the credential leak discovery by mocking the SpyCloud API."""
        # Arrange: Provide a mock API key and a simulated successful API response

        mock_api_keys.spycloud_api_key = "fake_spycloud_key"
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "num_results": 1,
            "results": [
                {
                    "email": "test@example.com",
                    "source_id": "12345",
                    "password": "password123",
                    "password_type": "plaintext",
                }
            ],
        }
        mock_get.return_value = mock_response

        # Act: Call the function

        result = find_credential_leaks("example.com")

        # Assert: Verify the API response was parsed correctly

        self.assertIsNotNone(result)
        self.assertEqual(result.total_found, 1)
        self.assertIsInstance(result.compromised_credentials[0], CompromisedCredential)
        self.assertTrue(result.compromised_credentials[0].is_plaintext)
        self.assertEqual(result.compromised_credentials[0].email, "test@example.com")

    @patch("chimera_intel.core.recon.API_KEYS")
    def test_find_credential_leaks_no_api_key(self, mock_api_keys):
        """Tests that the function returns an error if the API key is missing."""
        # Arrange: Set the API key to None

        mock_api_keys.spycloud_api_key = None

        # Act: Call the function

        result = find_credential_leaks("example.com")

        # Assert: Check that an appropriate error is returned

        self.assertIsNotNone(result.error)
        self.assertIn("SpyCloud API key not found", result.error)

    @patch("chimera_intel.core.recon.search_google_play")
    def test_find_digital_assets_success(self, mock_play_search):
        """Tests the digital asset discovery by mocking the google-play-scraper."""
        # Arrange: Simulate a successful response from the scraper

        mock_play_search.return_value = [
            {
                "title": "Example Official App",
                "appId": "com.example.app",
                "developer": "Example Corp",
            }
        ]

        # Act: Call the async function

        result = asyncio.run(find_digital_assets("Example Corp"))

        # Assert: Verify the scraper response was parsed correctly

        self.assertIsNotNone(result)
        self.assertEqual(len(result.mobile_apps), 1)
        self.assertIsInstance(result.mobile_apps[0], MobileApp)
        self.assertEqual(result.mobile_apps[0].app_id, "com.example.app")

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.async_client.get", new_callable=AsyncMock)
    async def test_analyze_threat_infrastructure_success(
        self, mock_async_get, mock_api_keys
    ):
        """Tests threat infrastructure analysis by mocking the VirusTotal API."""
        # Arrange: Provide a mock API key and a successful API response

        mock_api_keys.virustotal_api_key = "fake_vt_key"
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "data": [{"attributes": {"ip_address": "1.2.3.4"}}]
        }
        mock_async_get.return_value = mock_response

        # Act: Call the async function with a domain

        result = await analyze_threat_infrastructure("bad-domain.com")

        # Assert: Verify the API response was parsed correctly

        self.assertIsNotNone(result)
        self.assertEqual(len(result.related_indicators), 1)
        self.assertIsInstance(result.related_indicators[0], RelatedIndicator)
        self.assertEqual(result.related_indicators[0].value, "1.2.3.4")
        self.assertEqual(result.related_indicators[0].indicator_type, "IP Address")


if __name__ == "__main__":
    unittest.main()
