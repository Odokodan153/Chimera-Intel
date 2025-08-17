"""
Unit tests for the 'web_analyzer' module.

This test suite verifies the functionality of the asynchronous data gathering
functions in 'chimera_intel.core.web_analyzer.py'. It uses 'unittest.mock'
to simulate API responses, ensuring the tests are fast and independent of
live network conditions.
"""

import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

# Use the absolute import path for the package structure

from chimera_intel.core.web_analyzer import (
    get_tech_stack_builtwith,
    get_traffic_similarweb,
)


class TestWebAnalyzer(unittest.TestCase):
    """Test cases for web analysis functions."""

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    def test_get_tech_stack_builtwith_success(self, mock_async_get):
        """
        Tests a successful async call to the BuiltWith API.

        This test mocks the 'async_client.get' method to simulate a successful
        API response containing a list of web technologies.
        """
        # --- Simulate a successful API response ---

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Results": [
                {
                    "Result": {
                        "Paths": [
                            {"Technologies": [{"Name": "Nginx"}, {"Name": "React"}]}
                        ]
                    }
                }
            ]
        }
        # Configure the AsyncMock to return our simulated response

        mock_async_get.return_value = mock_response

        # --- Run the async function ---

        result = asyncio.run(get_tech_stack_builtwith("example.com", "fake_api_key"))

        # --- Assert against the actual returned list ---

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIn("Nginx", result)

    def test_get_tech_stack_builtwith_no_key(self):
        """
        Tests the defensive check for a missing API key.

        This test ensures that the function returns an empty list and does not
        attempt a network call when no API key is provided.
        """
        result = asyncio.run(get_tech_stack_builtwith("example.com", ""))
        self.assertEqual(result, [])  # It should return an empty list

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    def test_get_traffic_similarweb_success(self, mock_async_get):
        """
        Tests a successful async call to the Similarweb API.

        This test mocks the 'async_client.get' method to simulate a successful
        API response containing website traffic data.
        """
        # --- Simulate a successful API response ---

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"visits": "some_traffic_data"}

        # Configure the AsyncMock to return our simulated response

        mock_async_get.return_value = mock_response

        # --- Run the async function ---

        result = asyncio.run(get_traffic_similarweb("example.com", "fake_api_key"))

        # --- Assert the structure of the returned dictionary ---

        self.assertIn("visits", result)


if __name__ == "__main__":
    unittest.main()
