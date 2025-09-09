import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response, RequestError
from typer.testing import CliRunner

from chimera_intel.cli import app
from chimera_intel.core.recon import (
    find_credential_leaks,
    find_digital_assets,
    analyze_threat_infrastructure,
)
from chimera_intel.core.schemas import (
    CredentialExposureResult,
    AssetIntelResult,
    ThreatInfraResult,
)

# Initialize the Typer runner for CLI tests


runner = CliRunner()


class TestRecon(unittest.IsolatedAsyncioTestCase):
    """Extended test cases for the advanced reconnaissance module."""

    # --- Tests for find_credential_leaks ---

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.sync_client.get")
    def test_find_credential_leaks_success(self, mock_get, mock_api_keys):
        """Tests a successful credential leak discovery."""
        mock_api_keys.spycloud_api_key = "fake_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "num_results": 1,
            "results": [{"email": "test@example.com", "source_id": "breach1"}],
        }
        mock_get.return_value = mock_response

        result = find_credential_leaks("example.com")
        self.assertIsInstance(result, CredentialExposureResult)
        self.assertEqual(result.total_found, 1)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.sync_client.get")
    def test_find_credential_leaks_api_error(self, mock_get, mock_api_keys):
        """Tests credential leak discovery when the API returns an error."""
        mock_api_keys.spycloud_api_key = "fake_key"
        mock_get.side_effect = RequestError("API is down")

        result = find_credential_leaks("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the SpyCloud API", result.error)

    @patch("chimera_intel.core.recon.API_KEYS")
    def test_find_credential_leaks_no_api_key(self, mock_api_keys):
        """Tests credential leak discovery with a missing API key."""
        mock_api_keys.spycloud_api_key = None
        result = find_credential_leaks("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("SpyCloud API key not found", result.error)

    # --- Tests for find_digital_assets ---

    @patch("chimera_intel.core.recon.asyncio.to_thread")
    async def test_find_digital_assets_success(self, mock_to_thread):
        """Tests a successful digital asset discovery."""
        mock_to_thread.return_value = [
            {"title": "Test App", "appId": "com.test", "developer": "Example Corp"}
        ]
        result = await find_digital_assets("Example Corp")
        self.assertIsInstance(result, AssetIntelResult)
        self.assertEqual(len(result.mobile_apps), 1)
        self.assertEqual(result.mobile_apps[0].app_name, "Test App")

    @patch("chimera_intel.core.recon.asyncio.to_thread")
    async def test_find_digital_assets_scraper_error(self, mock_to_thread):
        """Tests digital asset discovery when the scraper raises an exception."""
        mock_to_thread.side_effect = Exception("Scraper failed")
        result = await find_digital_assets("Example Corp")
        self.assertEqual(len(result.mobile_apps), 0)  # Should gracefully handle error

    # --- Tests for analyze_threat_infrastructure ---

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.async_client.get", new_callable=AsyncMock)
    async def test_analyze_threat_infra_success_domain(
        self, mock_async_get, mock_api_keys
    ):
        """Tests a successful threat infrastructure analysis for a domain."""
        mock_api_keys.virustotal_api_key = "fake_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "data": [{"attributes": {"ip_address": "1.2.3.4"}}]
        }
        mock_async_get.return_value = mock_response
        result = await analyze_threat_infrastructure("example.com")
        self.assertIsInstance(result, ThreatInfraResult)
        self.assertEqual(len(result.related_indicators), 1)
        self.assertEqual(result.related_indicators[0].value, "1.2.3.4")

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.async_client.get", new_callable=AsyncMock)
    async def test_analyze_threat_infra_api_error(self, mock_async_get, mock_api_keys):
        """Tests threat infra analysis when the API returns an error."""
        mock_api_keys.virustotal_api_key = "fake_key"
        mock_async_get.side_effect = RequestError("VT API down")
        result = await analyze_threat_infrastructure("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the VirusTotal API", result.error)

    @patch("chimera_intel.core.recon.API_KEYS")
    async def test_analyze_threat_infra_no_api_key(self, mock_api_keys):
        """Tests threat infrastructure analysis with a missing API key."""
        mock_api_keys.virustotal_api_key = None
        result = await analyze_threat_infrastructure("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("VirusTotal API key not found", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.recon.find_credential_leaks")
    def test_cli_credentials_command_success(self, mock_find_leaks):
        """Tests the 'recon credentials' CLI command."""
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "target_domain": "example.com",
            "total_found": 5,
        }
        mock_find_leaks.return_value = mock_result

        cli_result = runner.invoke(app, ["recon", "credentials", "example.com"])
        self.assertEqual(cli_result.exit_code, 0)
        self.assertIn('"total_found": 5', cli_result.stdout)

    @patch("chimera_intel.core.recon.asyncio.run")
    def test_cli_assets_command_success(self, mock_asyncio_run):
        """Tests the 'recon assets' CLI command."""
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "target_company": "Example Corp",
            "mobile_apps": [],
        }
        mock_asyncio_run.return_value = mock_result

        cli_result = runner.invoke(app, ["recon", "assets", "Example Corp"])
        self.assertEqual(cli_result.exit_code, 0)
        self.assertIn('"target_company": "Example Corp"', cli_result.stdout)

    @patch("chimera_intel.core.recon.asyncio.run")
    def test_cli_threat_infra_command_success(self, mock_asyncio_run):
        """Tests the 'recon threat-infra' CLI command."""
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "initial_indicator": "1.2.3.4",
            "related_indicators": [],
        }
        mock_asyncio_run.return_value = mock_result

        cli_result = runner.invoke(app, ["recon", "threat-infra", "1.2.3.4"])
        self.assertEqual(cli_result.exit_code, 0)
        self.assertIn('"initial_indicator": "1.2.3.4"', cli_result.stdout)


if __name__ == "__main__":
    unittest.main()
