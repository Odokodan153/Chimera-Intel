# tests/test_offensive.py


import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import Response
import dns.resolver

# Import the functions to be tested


from chimera_intel.core.offensive import (
    discover_apis,
    enumerate_directories,
    check_subdomain_takeover,
)
from chimera_intel.core.schemas import (
    DiscoveredAPI,
    DiscoveredContent,
    SubdomainTakeoverResult,
)


class TestOffensive(unittest.TestCase):
    """Test cases for the offensive intelligence module."""

    @patch("chimera_intel.core.offensive.async_client.head", new_callable=AsyncMock)
    def test_discover_apis_success(self, mock_head):
        """Tests the API discovery function by mocking HEAD requests."""
        # Arrange: Simulate that only the /graphql endpoint is found (returns 200)

        async def side_effect(url, **kwargs):
            if "graphql" in str(url):
                return MagicMock(spec=Response, status_code=200)
            return MagicMock(spec=Response, status_code=404)

        mock_head.side_effect = side_effect

        # Act

        result = asyncio.run(discover_apis("example.com"))

        # Assert

        self.assertEqual(len(result.discovered_apis), 1)
        self.assertIsInstance(result.discovered_apis[0], DiscoveredAPI)
        self.assertEqual(result.discovered_apis[0].api_type, "GraphQL")

    @patch("chimera_intel.core.offensive.async_client.head", new_callable=AsyncMock)
    def test_enumerate_directories_success(self, mock_head):
        """Tests the content enumeration function by mocking HEAD requests."""
        # Arrange: Simulate that /admin and /.env are found, but others are not.

        async def side_effect(url, **kwargs):
            if "/admin" in str(url):
                return MagicMock(
                    spec=Response, status_code=403, headers={"content-length": "128"}
                )
            if "/.env" in str(url):
                return MagicMock(
                    spec=Response, status_code=200, headers={"content-length": "512"}
                )
            return MagicMock(spec=Response, status_code=404)

        mock_head.side_effect = side_effect

        # Act

        result = asyncio.run(enumerate_directories("example.com"))

        # Assert

        self.assertIsNotNone(result)
        self.assertEqual(len(result.found_content), 2)
        self.assertIsInstance(result.found_content[0], DiscoveredContent)

        # Check that one of the found URLs is the admin page

        found_urls = [content.url for content in result.found_content]
        self.assertIn("https://example.com/admin", found_urls)

    @patch("chimera_intel.core.offensive.async_client.get", new_callable=AsyncMock)
    @patch("chimera_intel.core.offensive.asyncio.to_thread")
    def test_check_subdomain_takeover_success(self, mock_to_thread, mock_async_get):
        """Tests the subdomain takeover check by mocking DNS and HTTP calls."""
        # Arrange

        # 1. Mock the DNS CNAME lookup

        mock_cname_answer = MagicMock()
        mock_cname_answer.target = "non-existent-bucket.s3.amazonaws.com"
        # We use side_effect to return different results based on the subdomain being checked

        def dns_side_effect(func, domain, rdtype):
            if domain == "assets.example.com" and rdtype == "CNAME":
                return [mock_cname_answer]
            raise dns.resolver.NXDOMAIN  # Simulate other subdomains not existing

        mock_to_thread.side_effect = dns_side_effect

        # 2. Mock the HTTP GET request to the subdomain

        mock_response = MagicMock(spec=Response)
        mock_response.text = "<html><body><h1>NoSuchBucket</h1><p>The specified bucket does not exist.</p></body></html>"
        mock_async_get.return_value = mock_response

        # Act

        result = asyncio.run(check_subdomain_takeover("example.com"))

        # Assert

        self.assertIsNotNone(result)
        self.assertEqual(len(result.potential_takeovers), 1)
        self.assertIsInstance(result.potential_takeovers[0], SubdomainTakeoverResult)
        self.assertEqual(result.potential_takeovers[0].vulnerable_service, "S3 Bucket")
        self.assertIn("NoSuchBucket", result.potential_takeovers[0].details)


if __name__ == "__main__":
    unittest.main()
