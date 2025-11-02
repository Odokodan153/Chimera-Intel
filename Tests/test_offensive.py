import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
import socket

from chimera_intel.core.offensive import (
    discover_apis,
    enumerate_content,
    check_for_subdomain_takeover,
    offensive_app,
)
from chimera_intel.core.schemas import (
    APIDiscoveryResult,
    ContentEnumerationResult,
    AdvancedCloudResult,
    SubdomainTakeoverResult,
)

runner = CliRunner()


class TestOffensive(unittest.IsolatedAsyncioTestCase):
    """Test cases for the offensive intelligence module."""

    # --- API Discovery Tests ---

    # FIX: Patch 'async_client.head', not '.get'
    @patch("chimera_intel.core.offensive.async_client.head", new_callable=AsyncMock)
    async def test_discover_apis_success(self, mock_head):
        """Tests successful API discovery."""
        # Arrange

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_404 = MagicMock()
        mock_response_404.status_code = 404
        
        # Simulate checking 6 endpoints: 1 found, 5 not found
        mock_head.side_effect = [
            mock_response_200, mock_response_404, mock_response_404,
            mock_response_404, mock_response_404, mock_response_404,
        ]

        # Act

        result = await discover_apis("example.com")

        # Assert

        self.assertIsInstance(result, APIDiscoveryResult)
        self.assertEqual(len(result.discovered_apis), 1)
        self.assertEqual(result.discovered_apis[0].api_type, "Swagger/OpenAPI")
        self.assertEqual(result.discovered_apis[0].status_code, 200)

    # --- Content Enumeration Tests ---

    # FIX: Patch 'async_client.head', not '.get'
    @patch("chimera_intel.core.offensive.async_client.head", new_callable=AsyncMock)
    async def test_enumerate_content_success(self, mock_head):
        """Tests successful content enumeration."""
        # Arrange

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_200.headers = {"content-length": "1024"}
        mock_response_404 = MagicMock()
        mock_response_404.status_code = 404
        
        # Simulate checking all paths. Let's say 2 are found.
        # Total paths = 12.
        mock_head.side_effect = [
            mock_response_200, mock_response_404, mock_response_404,
            mock_response_404, mock_response_404, mock_response_404,
            mock_response_404, mock_response_200, mock_response_404,
            mock_response_404, mock_response_404, mock_response_404,
        ]

        # Act

        result = await enumerate_content("example.com") # Base domain is fine

        # Assert

        self.assertIsInstance(result, ContentEnumerationResult)
        self.assertEqual(len(result.found_content), 2)
        self.assertEqual(result.found_content[0].status_code, 200)
        self.assertEqual(result.found_content[0].content_length, 1024)
        self.assertEqual(result.found_content[0].url, "https://example.com/admin")
        self.assertEqual(result.found_content[1].url, "https://example.com/.git/config")


    # --- Subdomain Takeover Tests ---

    @patch("chimera_intel.core.offensive.async_client.get", new_callable=AsyncMock)
    @patch("chimera_intel.core.offensive.asyncio.to_thread")
    async def test_check_for_subdomain_takeover_vulnerable(self, mock_to_thread, mock_get):
        """Tests detection of a vulnerable subdomain by resolution failure."""
        # Arrange
        # Simulate 'resolver.resolve' raising gaierror, indicating a dangling CNAME
        mock_to_thread.side_effect = socket.gaierror

        # Act
        # Pass the base domain and the specific list of subdomains to check
        result = await check_for_subdomain_takeover(
            "example.com", subdomains_to_check=["sub"]
        )

        # Assert
        self.assertIsInstance(result, AdvancedCloudResult)
        self.assertEqual(len(result.potential_takeovers), 1)
        self.assertEqual(result.potential_takeovers[0].subdomain, "sub.example.com")
        self.assertIn("Resolution Failure", result.potential_takeovers[0].vulnerable_service)


    # --- CLI Tests ---

    @patch("chimera_intel.core.offensive.asyncio.run")
    @patch("chimera_intel.core.offensive.save_scan_to_db")
    def test_cli_discover_apis_success(self, mock_save_db, mock_async_run):
        """Tests the 'offensive discover-apis' CLI command."""
        # Arrange
        mock_async_run.return_value = APIDiscoveryResult(
            target_domain="example.com", discovered_apis=[]
        )

        # Act
        result = runner.invoke(offensive_app, ["api-discover", "example.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"target_domain": "example.com"', result.stdout)
        mock_save_db.assert_called_once() # Verify DB save is called


    @patch("chimera_intel.core.offensive.asyncio.run")
    @patch("chimera_intel.core.offensive.save_scan_to_db")
    def test_cli_enumerate_content_success(self, mock_save_db, mock_async_run):
        """Tests the 'offensive enumerate-content' CLI command."""
        # Arrange
        mock_async_run.return_value = ContentEnumerationResult(
            target_url="https://example.com", found_content=[]
        )

        # Act
        result = runner.invoke(offensive_app, ["enum-content", "example.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"target_url": "https://example.com"', result.stdout)
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.offensive.asyncio.run")
    @patch("chimera_intel.core.offensive.save_scan_to_db")
    def test_cli_subdomain_takeover_success(self, mock_save_db, mock_async_run):
        """Tests the 'offensive subdomain-takeover' CLI command."""
        # Arrange
        mock_async_run.return_value = AdvancedCloudResult(
            target_domain="example.com",  # Base domain
            potential_takeovers=[
                SubdomainTakeoverResult(
                    subdomain="sub.example.com", vulnerable_service="N/A", details=""
                )
            ],
        )

        # Act
        result = runner.invoke(offensive_app, ["cloud-takeover", "example.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"subdomain": "sub.example.com"', result.stdout)
        self.assertIn('"vulnerable_service": "N/A"', result.stdout)
        mock_save_db.assert_called_once()

    # --- New Test for WiFi Attack Surface ---

    @patch("chimera_intel.core.offensive.get_data_by_module")
    @patch("chimera_intel.core.offensive.save_scan_to_db")
    def test_cli_wifi_attack_surface_success(self, mock_save_db, mock_get_data):
        """Tests the 'wifi-attack-surface' CLI command."""
        # Arrange
        mock_sigint_data = [
            {"ssid": "CORP-GUEST", "security_type": "Open"},
            {"ssid": "CORP-INTERNAL", "security_type": "WPA2-PSK (AES)"}
        ]
        mock_get_data.return_value = mock_sigint_data

        # Act
        result = runner.invoke(offensive_app, ["wifi-attack-surface", "Corporate-HQ"])
        
        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Modeling WiFi attack surface for Corporate-HQ", result.stdout)
        self.assertIn("Weak/Outdated Encryption", result.stdout)
        self.assertIn("CORP-GUEST", result.stdout)
        self.assertIn("Rogue Access Point / Evil Twin", result.stdout)
        self.assertIn("CORP-INTERNAL", result.stdout)
        
        # Verify it fetched data and saved the analysis
        mock_get_data.assert_called_once_with("Corporate-HQ", "sigint_wifi_scan")
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.offensive.get_data_by_module")
    def test_cli_wifi_attack_surface_no_data(self, mock_get_data):
        """Tests the wifi command when no SIGINT data is found."""
        # Arrange
        mock_get_data.return_value = None # No data

        # Act
        result = runner.invoke(offensive_app, ["wifi-attack-surface", "NoData-HQ"])
        
        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("No SIGINT (WiFi) data found for target 'NoData-HQ'", result.stdout)


if __name__ == "__main__":
    unittest.main()