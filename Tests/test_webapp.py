"""
Unit tests for the Chimera Intel FastAPI web application.

This test suite verifies the functionality of the API endpoints defined in
'webapp/main.py'. It uses 'unittest.mock' to isolate the API from the
database and core scanning logic, ensuring that tests are fast, deterministic,
and focus solely on the API layer's behavior.
"""

import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import AsyncClient

# Import the FastAPI application instance to be tested

from chimera_intel.webapp.main import app
from chimera_intel.core.schemas import FootprintResult, FootprintData, SubdomainReport


class TestWebApp(unittest.TestCase):
    """Test cases for the FastAPI web application endpoints."""

    @patch("chimera_intel.webapp.main.get_scan_history")
    def test_get_history_endpoint(self, mock_get_history: MagicMock):
        """Tests the `/api/history` endpoint for successful data retrieval.

        This test ensures that the endpoint correctly calls the database function
        and returns a properly formatted JSON response with the scan history.

        Args:
            mock_get_history (MagicMock): A mock for the `get_scan_history` function.
        """
        # Arrange: Mock the database function to return sample data

        mock_get_history.return_value = [
            {
                "id": 1,
                "target": "example.com",
                "module": "footprint",
                "timestamp": "2023-01-01T12:00:00",
            }
        ]

        async def run_test():
            # Act: Make a request to the endpoint using the test client

            async with AsyncClient(app=app, base_url="http://test") as ac:
                response = await ac.get("/api/history")
            # Assert: Check the response status and content

            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["target"], "example.com")
            mock_get_history.assert_called_once()

        # Run the async test case

        asyncio.run(run_test())

    @patch("chimera_intel.webapp.main.gather_footprint_data", new_callable=AsyncMock)
    def test_post_scan_endpoint_success(self, mock_gather_footprint: AsyncMock):
        """Tests the `/api/scan` endpoint with a valid request.

        This test ensures that the scan endpoint correctly triggers the appropriate
        scanning function based on the request payload and returns the scan results.

        Args:
            mock_gather_footprint (AsyncMock): A mock for the core `gather_footprint_data` function.
        """
        # Arrange: Mock the core scanning function to return a dummy result

        mock_result = FootprintResult(
            domain="example.com",
            footprint=FootprintData(
                whois_info={},
                dns_records={},
                subdomains=SubdomainReport(total_unique=0, results=[]),
                ip_threat_intelligence=[],
            ),
        )
        mock_gather_footprint.return_value = mock_result

        async def run_test():
            # Act: Post a valid scan request to the endpoint

            payload = {"domain": "example.com", "scan_type": "footprint"}
            async with AsyncClient(app=app, base_url="http://test") as ac:
                response = await ac.post("/api/scan", json=payload)
            # Assert: Check the response

            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data["domain"], "example.com")
            mock_gather_footprint.assert_called_once_with("example.com")

        asyncio.run(run_test())

    def test_post_scan_endpoint_invalid_domain(self):
        """Tests the `/api/scan` endpoint with an invalid domain format.

        This test verifies that the API correctly rejects requests with invalid
        domain names and returns an appropriate error status code.
        """

        async def run_test():
            payload = {"domain": "invalid-domain", "scan_type": "footprint"}
            async with AsyncClient(app=app, base_url="http://test") as ac:
                response = await ac.post("/api/scan", json=payload)
            self.assertEqual(response.status_code, 400)
            self.assertIn("Invalid domain format", response.json()["error"])

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
