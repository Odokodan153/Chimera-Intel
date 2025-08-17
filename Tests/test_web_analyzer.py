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
from httpx import RequestError, HTTPStatusError, Response

# Use the absolute import path for the package structure

from chimera_intel.core.web_analyzer import (
    get_tech_stack_builtwith,
    get_tech_stack_wappalyzer,
    get_traffic_similarweb,
)


class TestWebAnalyzer(unittest.TestCase):
    """Test cases for web analysis functions."""

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    def test_get_tech_stack_builtwith_success(self, mock_async_get):
        """
        Tests a successful async call to the BuiltWith API.
        """
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
        mock_async_get.return_value = mock_response

        result = asyncio.run(get_tech_stack_builtwith("example.com", "fake_api_key"))

        self.assertIsInstance(result, list)
        self.assertIn("Nginx", result)
        self.assertIn("React", result)

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    def test_get_tech_stack_builtwith_api_error(self, mock_async_get):
        """
        Tests the BuiltWith call when the API returns an error.
        """
        mock_response = MagicMock()
        http_error = HTTPStatusError(
            "Server Error", request=MagicMock(), response=Response(status_code=500)
        )
        mock_response.raise_for_status.side_effect = http_error
        mock_async_get.return_value = mock_response

        result = asyncio.run(get_tech_stack_builtwith("example.com", "fake_api_key"))
        self.assertEqual(result, [])

    def test_get_tech_stack_builtwith_no_key(self):
        """
        Tests the defensive check for a missing API key for BuiltWith.
        """
        result = asyncio.run(get_tech_stack_builtwith("example.com", ""))
        self.assertEqual(result, [])

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    def test_get_tech_stack_wappalyzer_success(self, mock_async_get):
        """
        Tests a successful async call to the Wappalyzer API.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"technologies": [{"name": "jQuery"}, {"name": "Vue.js"}]}
        ]
        mock_async_get.return_value = mock_response

        result = asyncio.run(get_tech_stack_wappalyzer("example.com", "fake_api_key"))
        self.assertIsInstance(result, list)
        self.assertIn("jQuery", result)

    def test_get_tech_stack_wappalyzer_no_key(self):
        """
        Tests the defensive check for a missing Wappalyzer API key.
        """
        result = asyncio.run(get_tech_stack_wappalyzer("example.com", ""))
        self.assertEqual(result, [])

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    def test_get_traffic_similarweb_success(self, mock_async_get):
        """
        Tests a successful async call to the Similarweb API.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"visits": "some_traffic_data"}
        mock_async_get.return_value = mock_response

        result = asyncio.run(get_traffic_similarweb("example.com", "fake_api_key"))
        self.assertIn("visits", result)

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    def test_get_traffic_similarweb_network_error(self, mock_async_get):
        """
        Tests the Similarweb call during a network error.
        """
        mock_async_get.side_effect = RequestError("Connection timeout")
        result = asyncio.run(get_traffic_similarweb("example.com", "fake_api_key"))
        self.assertIn("error", result)
        self.assertIn("An error occurred", result["error"])

    def test_get_traffic_similarweb_no_key(self):
        """
        Tests the Similarweb call when no API key is provided.
        """
        result = asyncio.run(get_traffic_similarweb("example.com", ""))
        self.assertIn("error", result)
        self.assertIn("API key not found", result["error"])


if __name__ == "__main__":
    unittest.main()
