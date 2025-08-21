import unittest
import time
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner

from chimera_intel.cli import app
from chimera_intel.core.web_analyzer import (
    get_tech_stack_builtwith,
    get_tech_stack_wappalyzer,
    get_traffic_similarweb,
    gather_web_analysis_data,
    take_screenshot,
    API_CACHE,
    CACHE_TTL_SECONDS,
)

runner = CliRunner()


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

    @patch("chimera_intel.core.web_analyzer.async_playwright")
    async def test_take_screenshot_success(self, mock_playwright):
        """Tests a successful screenshot."""
        # Create a complex mock for the async context manager and chained calls

        mock_browser = AsyncMock()
        mock_page = AsyncMock()
        mock_playwright.return_value.__aenter__.return_value.chromium.launch.return_value = (
            mock_browser
        )
        mock_browser.new_page.return_value = mock_page

        result = await take_screenshot("example.com")

        self.assertIsNotNone(result)
        self.assertIn("example_com", result)
        self.assertIn(".png", result)
        mock_page.goto.assert_called_once()
        mock_page.screenshot.assert_called_once()
        mock_browser.close.assert_called_once()

    @patch("chimera_intel.core.web_analyzer.async_playwright")
    async def test_take_screenshot_failure(self, mock_playwright):
        """Tests screenshot failure."""
        mock_playwright.return_value.__aenter__.return_value.chromium.launch.side_effect = Exception(
            "Browser launch failed"
        )

        result = await take_screenshot("example.com")

        self.assertIsNone(result)

    # CLI Tests

    @patch(
        "chimera_intel.core.web_analyzer.gather_web_analysis_data",
        new_callable=AsyncMock,
    )
    def test_cli_web_run_success(self, mock_gather):
        """Tests the 'web run' CLI command for a successful scan."""
        mock_result_model = MagicMock()
        mock_result_model.model_dump.return_value = {
            "domain": "example.com",
            "web_analysis": {},
        }
        mock_gather.return_value = mock_result_model

        result = runner.invoke(app, ["scan", "web", "run", "example.com"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"domain": "example.com"', result.stdout)

    def test_cli_web_run_invalid_domain(self):
        """Tests the 'web run' CLI command with an invalid domain."""
        result = runner.invoke(app, ["scan", "web", "run", "invalid-domain"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)


if __name__ == "__main__":
    unittest.main()
