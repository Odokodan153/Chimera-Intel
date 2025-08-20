"""
Unit tests for the 'web_analyzer' module.

This test suite verifies the functionality of the asynchronous data gathering
functions in 'chimera_intel.core.web_analyzer.py'. It uses 'unittest.mock'
to simulate API responses, ensuring the tests are fast and independent of
live network conditions.
"""

import unittest
import asyncio
import time
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import RequestError, HTTPStatusError, Response

# Use the absolute import path for the package structure

from chimera_intel.core.web_analyzer import (
    get_tech_stack_builtwith,
    get_tech_stack_wappalyzer,
    get_traffic_similarweb,
    gather_web_analysis_data,
    API_CACHE,
    CACHE_TTL_SECONDS,  # Import cache for testing
)


class TestWebAnalyzer(unittest.TestCase):
    """Test cases for web analysis functions."""

    def setUp(self):
        """Clear the cache before each test to ensure test isolation."""
        API_CACHE.clear()

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_get_tech_stack_builtwith_success(self, mock_async_get):
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

        result = await get_tech_stack_builtwith("example.com", "fake_api_key")

        self.assertIsInstance(result, list)
        self.assertIn("Nginx", result)
        self.assertIn("React", result)

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_get_tech_stack_builtwith_caches_result(self, mock_async_get):
        """Tests that a successful BuiltWith API call is cached."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Results": [{"Result": {"Paths": [{"Technologies": [{"Name": "React"}]}]}}]
        }
        mock_async_get.return_value = mock_response

        # First call - should call the API

        await get_tech_stack_builtwith("example.com", "fake_key")
        mock_async_get.assert_called_once()

        # Second call - should use the cache

        await get_tech_stack_builtwith("example.com", "fake_key")
        # Assert that the mock was NOT called again

        mock_async_get.assert_called_once()

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_cache_expires(self, mock_async_get):
        """Tests that the cache expires after the TTL."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"Results": []}
        mock_async_get.return_value = mock_response

        # First call

        await get_tech_stack_builtwith("anotherexample.com", "fake_key")
        self.assertEqual(mock_async_get.call_count, 1)

        # Manually expire the cache entry

        url = "https://api.builtwith.com/v21/api.json?KEY=fake_key&LOOKUP=anotherexample.com"
        API_CACHE[url]["timestamp"] = time.time() - CACHE_TTL_SECONDS - 1

        # Second call should re-call the API

        await get_tech_stack_builtwith("anotherexample.com", "fake_key")
        self.assertEqual(mock_async_get.call_count, 2)

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_get_tech_stack_wappalyzer_success(self, mock_async_get):
        """
        Tests a successful async call to the Wappalyzer API.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"technologies": [{"name": "jQuery"}, {"name": "Vue.js"}]}
        ]
        mock_async_get.return_value = mock_response

        result = await get_tech_stack_wappalyzer("example.com", "fake_api_key")
        self.assertIsInstance(result, list)
        self.assertIn("jQuery", result)

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_get_traffic_similarweb_success(self, mock_async_get):
        """
        Tests a successful async call to the Similarweb API.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"visits": "some_traffic_data"}
        mock_async_get.return_value = mock_response

        result = await get_traffic_similarweb("example.com", "fake_api_key")
        self.assertIn("visits", result)

    @patch("chimera_intel.core.web_analyzer.take_screenshot", new_callable=AsyncMock)
    @patch(
        "chimera_intel.core.web_analyzer.get_traffic_similarweb", new_callable=AsyncMock
    )
    @patch(
        "chimera_intel.core.web_analyzer.get_tech_stack_wappalyzer",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.web_analyzer.get_tech_stack_builtwith",
        new_callable=AsyncMock,
    )
    async def test_gather_web_analysis_data_all_sources(
        self, mock_builtwith, mock_wappalyzer, mock_similarweb, mock_screenshot
    ):
        """Tests the main data aggregation logic with all API keys present."""
        mock_builtwith.return_value = ["React", "Nginx"]
        mock_wappalyzer.return_value = ["React", "jQuery"]
        mock_similarweb.return_value = {"visits": 1000}
        mock_screenshot.return_value = "/path/to/screenshot.png"

        with patch("chimera_intel.core.web_analyzer.API_KEYS") as mock_keys:
            mock_keys.builtwith_api_key = "fake_key"
            mock_keys.wappalyzer_api_key = "fake_key"
            mock_keys.similarweb_api_key = "fake_key"

            result = await gather_web_analysis_data("example.com")

            self.assertEqual(result.web_analysis.tech_stack.total_unique, 3)
            self.assertEqual(result.web_analysis.traffic_info["visits"], 1000)
            self.assertEqual(
                result.web_analysis.screenshot_path, "/path/to/screenshot.png"
            )
            # Check for high confidence on 'React'

            for tech in result.web_analysis.tech_stack.results:
                if tech.technology == "React":
                    self.assertIn("HIGH", tech.confidence)


if __name__ == "__main__":
    # To run async tests, we need to use an async test runner.
    # unittest.main() can work if run with `python -m unittest`
    # or if we manually configure an event loop, but for simplicity,
    # relying on a test runner like pytest with pytest-asyncio is best.

    unittest.main()
