import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import Response
from chimera_intel.core.offensive import (
    discover_apis,
    enumerate_directories,
    check_subdomain_takeover,
)


class TestOffensive(unittest.TestCase):
    """Test cases for the offensive intelligence module."""

    @patch("chimera_intel.core.offensive.async_client.head", new_callable=AsyncMock)
    def test_discover_apis(self, mock_head):
        """Tests the API discovery function."""
        # Simulate that only the /graphql endpoint is found

        async def side_effect(url, **kwargs):
            if "graphql" in url:
                return MagicMock(spec=Response, status_code=200)
            return MagicMock(spec=Response, status_code=404)

        mock_head.side_effect = side_effect

        result = asyncio.run(discover_apis("example.com"))
        self.assertEqual(len(result.discovered_apis), 1)
        self.assertEqual(result.discovered_apis[0].api_type, "GraphQL")

    def test_enumerate_directories(self):
        """Tests the content enumeration function."""
        result = enumerate_directories("example.com")
        self.assertIsNotNone(result)
        self.assertEqual(len(result.found_content), 3)
        self.assertIn("/admin", result.found_content[0].url)

    def test_check_subdomain_takeover(self):
        """Tests the subdomain takeover check function."""
        result = check_subdomain_takeover("example.com")
        self.assertIsNotNone(result)
        self.assertEqual(len(result.potential_takeovers), 1)
        self.assertEqual(result.potential_takeovers[0].vulnerable_service, "S3 Bucket")


if __name__ == "__main__":
    unittest.main()
