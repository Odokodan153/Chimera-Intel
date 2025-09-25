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
    ProjectConfig,
)

# Initialize the Typer runner for CLI tests


runner = CliRunner()


@patch("kaggle.api.kaggle_api.KaggleApi.authenticate")
class TestRecon(unittest.IsolatedAsyncioTestCase):
    """Extended test cases for the advanced reconnaissance module."""

    # --- Tests for find_credential_leaks ---

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.sync_client.get")
    def test_find_credential_leaks_success(
        self, mock_get, mock_api_keys, mock_kaggle_auth
    ):
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
    def test_find_credential_leaks_api_error(
        self, mock_get, mock_api_keys, mock_kaggle_auth
    ):
        """Tests credential leak discovery when the API returns an error."""
        mock_api_keys.spycloud_api_key = "fake_key"
        mock_get.side_effect = RequestError("API is down")

        result = find_credential_leaks("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the SpyCloud API", result.error)

    @patch("chimera_intel.core.recon.API_KEYS")
    def test_find_credential_leaks_no_api_key(self, mock_api_keys, mock_kaggle_auth):
        """Tests credential leak discovery with a missing API key."""
        mock_api_keys.spycloud_api_key = None
        result = find_credential_leaks("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("SpyCloud API key not found", result.error)

    @patch("chimera_intel.core.recon.sync_client.get")
    def test_find_credential_leaks_exception(self, mock_get, mock_kaggle_auth):
        """Tests exception handling in find_credential_leaks."""
        mock_get.side_effect = Exception("Test exception")
        with patch(
            "chimera_intel.core.config_loader.API_KEYS.spycloud_api_key", "fake_key"
        ):
            result = find_credential_leaks("example.com")
            self.assertIsNotNone(result.error)

    # --- Tests for find_digital_assets (Rewritten) ---

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.kaggle.KaggleApi")
    @patch("chimera_intel.core.recon.search_google_play")
    async def test_find_digital_assets_success(
        self, mock_search_play, mock_kaggle_api, mock_api_keys, mock_kaggle_auth
    ):
        """Tests a successful digital asset discovery by mocking library calls."""
        # Arrange

        mock_api_keys.kaggle_api_key = "fake_kaggle_key"

        # Mock the google-play-scraper call

        mock_search_play.return_value = [
            {"title": "Test App", "appId": "com.test", "developer": "Example Corp"}
        ]

        # Mock the Kaggle API calls

        mock_kaggle_instance = mock_kaggle_api.return_value
        mock_dataset = MagicMock()
        mock_dataset.ref = "testuser/test-dataset"
        mock_kaggle_instance.dataset_list.return_value = [mock_dataset]

        # Act

        result = await find_digital_assets("Example Corp")

        # Assert

        self.assertIsInstance(result, AssetIntelResult)
        self.assertEqual(len(result.mobile_apps), 1)
        self.assertEqual(result.mobile_apps[0].app_name, "Test App")
        self.assertEqual(len(result.public_datasets), 1)
        self.assertEqual(result.public_datasets[0], "kaggle://testuser/test-dataset")

    @patch("chimera_intel.core.recon.asyncio.to_thread")
    async def test_find_digital_assets_scraper_error(
        self, mock_to_thread, mock_kaggle_auth
    ):
        """Tests digital asset discovery when the scraper raises an exception."""
        mock_to_thread.side_effect = Exception("Scraper failed")
        result = await find_digital_assets("Example Corp")
        self.assertEqual(len(result.mobile_apps), 0)  # Should gracefully handle error

    # --- Tests for analyze_threat_infrastructure ---

    @patch("chimera_intel.core.recon.API_KEYS")
    @patch("chimera_intel.core.recon.async_client.get", new_callable=AsyncMock)
    async def test_analyze_threat_infra_success_domain(
        self, mock_async_get, mock_api_keys, mock_kaggle_auth
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
    async def test_analyze_threat_infra_api_error(
        self, mock_async_get, mock_api_keys, mock_kaggle_auth
    ):
        """Tests threat infra analysis when the API returns an error."""
        mock_api_keys.virustotal_api_key = "fake_key"
        mock_async_get.side_effect = RequestError("VT API down")
        result = await analyze_threat_infrastructure("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the VirusTotal API", result.error)

    @patch("chimera_intel.core.recon.API_KEYS")
    async def test_analyze_threat_infra_no_api_key(
        self, mock_api_keys, mock_kaggle_auth
    ):
        """Tests threat infrastructure analysis with a missing API key."""
        mock_api_keys.virustotal_api_key = None
        result = await analyze_threat_infrastructure("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("VirusTotal API key not found", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.recon.find_credential_leaks")
    def test_cli_credentials_command_success(self, mock_find_leaks, mock_kaggle_auth):
        """Tests the 'recon credentials' CLI command with an explicit domain."""
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "target_domain": "example.com",
            "total_found": 5,
        }
        mock_find_leaks.return_value = mock_result

        cli_result = runner.invoke(app, ["recon", "credentials", "example.com"])
        self.assertEqual(cli_result.exit_code, 0)
        self.assertIn('"total_found": 5', cli_result.stdout)
        mock_find_leaks.assert_called_with("example.com")

    @patch("chimera_intel.core.recon.get_active_project")
    @patch("chimera_intel.core.recon.find_credential_leaks")
    def test_cli_credentials_with_project(
        self, mock_find_leaks, mock_get_project, mock_kaggle_auth
    ):
        """Tests the 'recon credentials' command using an active project."""
        mock_project = ProjectConfig(
            project_name="Test", created_at="", domain="project.com"
        )
        mock_get_project.return_value = mock_project
        mock_find_leaks.return_value.model_dump.return_value = {}

        result = runner.invoke(app, ["recon", "credentials"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using domain 'project.com'", result.stdout)
        mock_find_leaks.assert_called_with("project.com")

    @patch("chimera_intel.core.recon.asyncio.run")
    def test_cli_assets_command_success(self, mock_asyncio_run, mock_kaggle_auth):
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
    def test_cli_threat_infra_command_success(self, mock_asyncio_run, mock_kaggle_auth):
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
