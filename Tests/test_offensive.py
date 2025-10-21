import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
import json
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
        mock_head.side_effect = [mock_response_200, mock_response_404]

        # Act

        result = await discover_apis("example.com")

        # Assert

        self.assertIsInstance(result, APIDiscoveryResult)
        self.assertEqual(len(result.discovered_apis), 1)
        self.assertEqual(result.discovered_apis[0].api_type, "Swagger/OpenAPI")
        self.assertEqual(result.discovered_apis[0].status_code, 200)
        self.assertIsNone(result.error)

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
        mock_head.side_effect = [mock_response_200, mock_response_404]

        # Act

        result = await enumerate_content("http://example.com")

        # Assert

        self.assertIsInstance(result, ContentEnumerationResult)
        self.assertEqual(len(result.found_content), 1)
        self.assertEqual(result.found_content[0].status_code, 200)
        self.assertEqual(result.found_content[0].content_length, 1024)

    # --- Subdomain Takeover Tests ---

    # FIX: Patch the list of subdomains to check just one
    @patch("chimera_intel.core.offensive.subdomains_to_check", ["sub"])
    @patch("chimera_intel.core.offensive.asyncio.to_thread")
    async def test_check_for_subdomain_takeover_vulnerable(
        self, mock_to_thread, mock_subdomains_list
    ):
        """Tests detection of a vulnerable subdomain."""
        # Arrange
        # Simulate 'socket.gethostbyname' raising an error, indicating a dangling CNAME
        mock_to_thread.side_effect = socket.gaierror

        # Act
        # FIX: Pass the base domain, not the subdomain
        result = await check_for_subdomain_takeover("example.com")

        # Assert

        self.assertIsInstance(result, AdvancedCloudResult)
        # FIX: Now the length will be 1 as expected
        self.assertEqual(len(result.potential_takeovers), 1)
        self.assertEqual(result.potential_takeovers[0].subdomain, "sub.example.com")

    # --- CLI Tests ---

    @patch("chimera_intel.core.offensive.discover_apis", new_callable=AsyncMock)
    def test_cli_discover_apis_success(self, mock_discover):
        """Tests the 'offensive discover-apis' CLI command."""
        # Arrange

        mock_discover.return_value = APIDiscoveryResult(
            target_domain="example.com", discovered_apis=[]
        )

        # Act
        # FIX: Correct command name is 'api-discover'
        result = runner.invoke(offensive_app, ["api-discover", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"target_domain": "example.com"', result.stdout)
        mock_discover.assert_awaited_with("example.com")

    @patch("chimera_intel.core.offensive.enumerate_content", new_callable=AsyncMock)
    def test_cli_enumerate_content_success(self, mock_enumerate):
        """Tests the 'offensive enumerate-content' CLI command."""
        # Arrange

        mock_enumerate.return_value = ContentEnumerationResult(
            target_url="http://example.com", found_content=[]
        )

        # Act
        # FIX: Correct command name is 'enum-content'
        result = runner.invoke(
            offensive_app, ["enum-content", "http://example.com"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"target_url": "http://example.com"', result.stdout)

    @patch(
        "chimera_intel.core.offensive.check_for_subdomain_takeover",
        new_callable=AsyncMock,
    )
    def test_cli_subdomain_takeover_success(self, mock_check):
        """Tests the 'offensive subdomain-takeover' CLI command."""
        # Arrange

        mock_check.return_value = AdvancedCloudResult(
            target_domain="example.com",  # Base domain
            potential_takeovers=[
                SubdomainTakeoverResult(
                    subdomain="sub.example.com", vulnerable_service="N/A", details=""
                )
            ],
        )

        # Act
        # FIX: Correct command name is 'cloud-takeover'
        result = runner.invoke(offensive_app, ["cloud-takeover", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(len(output["potential_takeovers"]), 1)


if __name__ == "__main__":
    unittest.main()