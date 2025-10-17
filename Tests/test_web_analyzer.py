"""
Unit tests for the 'web_analyzer' module.

This test suite verifies the functionality of the asynchronous data gathering
functions in 'chimera_intel.core.web_analyzer.py'. It uses 'unittest.mock'
to simulate API responses, ensuring the tests are fast and independent of
live network conditions. It also includes tests for the CLI commands.
"""

import unittest
import time
from unittest.mock import patch, MagicMock, AsyncMock
from typer.testing import CliRunner
import typer
from httpx import Response

from chimera_intel.core.web_analyzer import web_app  # Import the specific app
from chimera_intel.core.web_analyzer import (
    get_tech_stack_builtwith,
    get_tech_stack_wappalyzer,
    get_traffic_similarweb,
    gather_web_analysis_data,
    analyze_tech_stack_risk,
    take_screenshot,
    API_CACHE,
    CACHE_TTL_SECONDS,
)

from chimera_intel.core.schemas import (
    WebAnalysisResult,
    TechStackRisk,
)


runner = CliRunner()


class TestWebAnalyzer(unittest.IsolatedAsyncioTestCase):
    """Test cases for web analysis functions and CLI commands."""

    def setUp(self):
        """Clear the cache before each test to ensure test isolation."""
        API_CACHE.clear()

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_get_tech_stack_builtwith_success(self, mock_async_get: AsyncMock):
        """
        Tests a successful asynchronous call to the BuiltWith API.

        Args:
            mock_async_get (AsyncMock): A mock for the `httpx.AsyncClient.get` method.
        """
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
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
    async def test_get_tech_stack_builtwith_caches_result(
        self, mock_async_get: AsyncMock
    ):
        """
        Tests that a successful BuiltWith API call is correctly cached.

        Args:
            mock_async_get (AsyncMock): A mock for the `httpx.AsyncClient.get` method.
        """
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "Results": [{"Result": {"Paths": [{"Technologies": [{"Name": "React"}]}]}}]
        }
        mock_async_get.return_value = mock_response

        # First call should trigger the API

        await get_tech_stack_builtwith("example.com", "fake_key")
        mock_async_get.assert_called_once()

        # Second call should be served from the cache

        await get_tech_stack_builtwith("example.com", "fake_key")
        mock_async_get.assert_called_once()  # Should not be called again

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_cache_expires(self, mock_async_get: AsyncMock):
        """
        Tests that the cache expires after the TTL has passed.

        Args:
            mock_async_get (AsyncMock): A mock for the `httpx.AsyncClient.get` method.
        """
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"Results": []}
        mock_async_get.return_value = mock_response

        # First call

        await get_tech_stack_builtwith("anotherexample.com", "fake_key")
        self.assertEqual(mock_async_get.call_count, 1)

        # Manually expire the cache entry

        url = "https://api.builtwith.com/v21/api.json?KEY=fake_key&LOOKUP=anotherexample.com"
        API_CACHE[url]["timestamp"] = time.time() - CACHE_TTL_SECONDS - 1

        # Second call should re-trigger the API

        await get_tech_stack_builtwith("anotherexample.com", "fake_key")
        self.assertEqual(mock_async_get.call_count, 2)

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_get_tech_stack_wappalyzer_success(self, mock_async_get: AsyncMock):
        """
        Tests a successful asynchronous call to the Wappalyzer API.

        Args:
            mock_async_get (AsyncMock): A mock for the `httpx.AsyncClient.get` method.
        """
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = [
            {"technologies": [{"name": "jQuery"}, {"name": "Vue.js"}]}
        ]
        mock_async_get.return_value = mock_response

        result = await get_tech_stack_wappalyzer("example.com", "fake_api_key")
        self.assertIsInstance(result, list)
        self.assertIn("jQuery", result)

    @patch("chimera_intel.core.web_analyzer.async_client.get", new_callable=AsyncMock)
    async def test_get_traffic_similarweb_success(self, mock_async_get: AsyncMock):
        """
        Tests a successful asynchronous call to the Similarweb API.

        Args:
            mock_async_get (AsyncMock): A mock for the `httpx.AsyncClient.get` method.
        """
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
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
        self,
        mock_builtwith: AsyncMock,
        mock_wappalyzer: AsyncMock,
        mock_similarweb: AsyncMock,
        mock_screenshot: AsyncMock,
    ):
        """
        Tests the main data aggregation logic with all API keys present.

        Args:
            mock_builtwith (AsyncMock): A mock for the BuiltWith data function.
            mock_wappalyzer (AsyncMock): A mock for the Wappalyzer data function.
            mock_similarweb (AsyncMock): A mock for the Similarweb data function.
            mock_screenshot (AsyncMock): A mock for the screenshot function.
        """
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
            for tech in result.web_analysis.tech_stack.results:
                if tech.technology == "React":
                    self.assertIn("HIGH", tech.confidence)

    @patch("chimera_intel.core.web_analyzer.async_playwright")
    async def test_take_screenshot_success(self, mock_playwright: MagicMock):
        """
        Tests a successful screenshot capture using a mocked Playwright instance.

        Args:
            mock_playwright (MagicMock): A mock for the `async_playwright` context manager.
        """
        mock_playwright_manager = AsyncMock()
        mock_playwright.return_value = mock_playwright_manager
        mock_browser = AsyncMock()
        (
            mock_playwright_manager.__aenter__.return_value.chromium.launch.return_value
        ) = mock_browser
        mock_page = AsyncMock()
        mock_browser.new_page.return_value = mock_page

        result = await take_screenshot("example.com")
        self.assertIsNotNone(result)

    @patch("chimera_intel.core.web_analyzer.async_playwright")
    async def test_take_screenshot_failure(self, mock_playwright: MagicMock):
        """
        Tests screenshot failure when Playwright raises an exception.

        Args:
            mock_playwright (MagicMock): A mock for the `async_playwright` context manager.
        """
        mock_playwright_manager = AsyncMock()
        mock_playwright.return_value = mock_playwright_manager
        (
            mock_playwright_manager.__aenter__.return_value.chromium.launch.side_effect
        ) = Exception("Browser launch failed")
        result = await take_screenshot("example.com")
        self.assertIsNone(result)

    @patch("chimera_intel.core.web_analyzer.resolve_target")
    @patch(
        "chimera_intel.core.web_analyzer.gather_web_analysis_data",
        new_callable=AsyncMock,
    )
    def test_cli_web_run_with_project(self, mock_gather_data, mock_resolve_target):
        """Tests the CLI command using the centralized target resolver."""
        # Arrange

        mock_resolve_target.return_value = "project.com"
        mock_gather_data.return_value.model_dump.return_value = {}

        # Act

        # FIX: The command being tested is 'run', which is part of 'web_app'.
        # The previous invocation was runner.invoke(web_app, ["run"]), which caused
        # the parser to mistake "run" for the 'domain' argument.
        # The correct invocation when no domain is provided is just runner.invoke(web_app).
        # Typer is smart enough to call the default/only command.

        result = runner.invoke(web_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        # Verify that our new central function was called

        mock_resolve_target.assert_called_once_with(None, required_assets=["domain"])
        # Verify the core logic was called with the resolved target

        mock_gather_data.assert_awaited_with("project.com")

    @patch("chimera_intel.core.web_analyzer.resolve_target")
    def test_cli_web_run_resolver_fails(self, mock_resolve_target):
        """Tests the CLI command when the resolver raises an exit exception."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act

        result = runner.invoke(web_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)

    def test_cli_web_run_invalid_domain(self):
        """Tests the 'scan web run' CLI command with an invalid domain, expecting an error."""
        # FIX: The command is 'run', and the argument is 'invalid-domain'.
        # The runner expects a list of strings for the arguments.

        result = runner.invoke(web_app, ["run", "invalid-domain"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("is not a valid domain format", result.stdout)

    # --- Function Tests ---

    @patch(
        "chimera_intel.core.web_analyzer.get_tech_stack_builtwith",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.web_analyzer.get_tech_stack_wappalyzer",
        new_callable=AsyncMock,
    )
    @patch(
        "chimera_intel.core.web_analyzer.get_traffic_similarweb", new_callable=AsyncMock
    )
    @patch("chimera_intel.core.web_analyzer.take_screenshot", new_callable=AsyncMock)
    async def test_gather_web_analysis_data_success(
        self, mock_screenshot, mock_similarweb, mock_wappalyzer, mock_builtwith
    ):
        """Tests the successful orchestration of web analysis data gathering."""
        # Arrange

        mock_builtwith.return_value = ["nginx", "jQuery"]
        mock_wappalyzer.return_value = ["nginx", "React"]
        mock_similarweb.return_value = {"visits": [1000, 2000]}
        mock_screenshot.return_value = "/screenshots/example_com.png"

        # Act
        # FIX: Added patch for API_KEYS which is required by the function

        with patch("chimera_intel.core.web_analyzer.API_KEYS") as mock_keys:
            mock_keys.builtwith_api_key = "fake_key"
            mock_keys.wappalyzer_api_key = "fake_key"
            mock_keys.similarweb_api_key = "fake_key"
            result = await gather_web_analysis_data("example.com")
        # Assert

        self.assertIsInstance(result, WebAnalysisResult)
        self.assertEqual(result.domain, "example.com")
        # nginx (2 sources), jQuery (1), React (1)

        self.assertEqual(result.web_analysis.tech_stack.total_unique, 3)
        self.assertEqual(
            result.web_analysis.screenshot_path, "/screenshots/example_com.png"
        )
        self.assertIn("visits", result.web_analysis.traffic_info)

    def test_analyze_tech_stack_risk(self):
        """Tests the rule-based technology risk assessment."""
        # Arrange

        technologies = ["WordPress 4.9", "PHP 5.6", "jQuery 1.12"]

        # Act

        risk_result = analyze_tech_stack_risk(technologies)

        # Assert

        self.assertIsInstance(risk_result, TechStackRisk)
        self.assertEqual(risk_result.risk_level, "Critical")
        self.assertEqual(risk_result.risk_score, 90)  # 40 (WP) + 30 (PHP) + 20 (jQuery)
        self.assertEqual(len(risk_result.details), 3)

    # --- CLI Tests ---

    @patch("chimera_intel.core.web_analyzer.resolve_target")
    @patch(
        "chimera_intel.core.web_analyzer.gather_web_analysis_data",
        new_callable=AsyncMock,
    )
    def test_cli_run_web_analysis_success(self, mock_gather, mock_resolve):
        """Tests a successful run of the 'web run' CLI command."""
        # Arrange

        mock_resolve.return_value = "example.com"
        # Mock the complex return object and its model_dump method

        mock_result_instance = MagicMock()
        mock_result_instance.model_dump.return_value = {
            "domain": "example.com",
            "web_analysis": {},
        }
        mock_gather.return_value = mock_result_instance

        # Act
        # FIX: Invoke 'run' and let the patched resolver handle the domain

        result = runner.invoke(web_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve.assert_called_once_with(None, required_assets=["domain"])
        mock_gather.assert_awaited_with("example.com")
        self.assertIn('"domain": "example.com"', result.stdout)

    @patch("chimera_intel.core.web_analyzer.resolve_target")
    def test_cli_run_invalid_domain(self, mock_resolve):
        """Tests the CLI command with an invalid domain."""
        # Arrange

        mock_resolve.return_value = "invalid-domain"

        # Act
        # FIX: Invoke 'run' and let the patched resolver provide the invalid domain

        result = runner.invoke(web_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)


if __name__ == "__main__":
    unittest.main()
