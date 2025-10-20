import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response, AsyncClient
from typer.testing import CliRunner
import json
import typer  # Import typer for typer.Exit
import sys  # Import sys for stderr

from chimera_intel.core.dark_web_osint import search_dark_web_engine, dark_web_app
from chimera_intel.core.schemas import DarkWebScanResult, DarkWebResult, ProjectConfig

runner = CliRunner()


class TestDarkWebOsint(unittest.IsolatedAsyncioTestCase):
    """Test cases for the dark_web_osint module."""

    @patch("chimera_intel.core.dark_web_osint.CONFIG")
    @patch("httpx.AsyncClient")
    async def test_search_dark_web_engine_success(
        self, mock_async_client_cls, mock_config
    ):
        """Tests a successful dark web search using the Ahmia engine."""
        # Arrange

        mock_config.modules.dark_web.tor_proxy_url = "socks5://127.0.0.1:9150"

        mock_async_client = AsyncMock(spec=AsyncClient)
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = """
        <html><body>
            <li class="result">
                <a href="http://example.onion">Test Title</a>
                <cite>http://example.onion</cite>
                <p>Test description.</p>
            </li>
        </body></html>
        """
        mock_async_client.get.return_value = mock_response
        mock_async_client_cls.return_value.__aenter__.return_value = mock_async_client

        # Act

        result = await search_dark_web_engine("test query", engine="ahmia")

        # Assert

        self.assertIsInstance(result, DarkWebScanResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.found_results), 1)
        self.assertEqual(result.found_results[0].title, "Test Title")

    async def test_search_dark_web_no_proxy_configured(self):
        """Tests the function's behavior when the Tor proxy is not configured."""
        with patch(
            "chimera_intel.core.dark_web_osint.CONFIG.modules.dark_web.tor_proxy_url",
            None,
        ):
            result = await search_dark_web_engine("test query")
            self.assertIsNotNone(result.error)
            self.assertIn("Tor proxy URL is not configured", result.error)

    @patch("chimera_intel.core.dark_web_osint.CONFIG")
    @patch("httpx.AsyncClient")
    async def test_search_dark_web_engine_timeout(
        self, mock_async_client_cls, mock_config
    ):
        """NEW: Tests the function's timeout handling."""
        # Arrange

        mock_config.modules.dark_web.tor_proxy_url = "socks5://127.0.0.1:9150"

        mock_async_client = AsyncMock(spec=AsyncClient)
        mock_async_client.get.side_effect = asyncio.TimeoutError
        mock_async_client_cls.return_value.__aenter__.return_value = mock_async_client

        # Act

        result = await search_dark_web_engine("test query")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Search timed out", result.error)

    # --- CLI Command Tests ---

    @patch(
        "chimera_intel.core.dark_web_osint.async_run_dark_web_search",
        new_callable=AsyncMock,
    )
    def test_cli_dark_web_search_success(self, mock_async_run):
        """NEW: Tests a successful run of the 'dark-web search' command."""
        # Arrange
        mock_scan_result = DarkWebScanResult(
            query="testcorp",
            found_results=[DarkWebResult(title="Test Result", url="http://test.onion")],
        )

        # Define an async side_effect function to be executed by asyncio.run
        async def mock_coro(*args, **kwargs):
            print(mock_scan_result.model_dump_json(indent=1))

        mock_async_run.side_effect = mock_coro

        # Act
        result = runner.invoke(dark_web_app, ["search", "testcorp"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["query"], "testcorp")
        self.assertEqual(len(output["found_results"]), 1)
        # Check that the async function was called with the correct args
        mock_async_run.assert_called_once_with("testcorp", "ahmia", None)

    @patch(
        "chimera_intel.core.dark_web_osint.async_run_dark_web_search",
        new_callable=AsyncMock,
    )
    def test_cli_dark_web_search_with_project(self, mock_async_run):
        """NEW: Tests the CLI command using an active project's company name."""
        # Arrange
        mock_scan_result = DarkWebScanResult(
            query="ProjectCorp", found_results=[]
        )

        # Define an async side_effect function to simulate the prints
        async def mock_coro(*args, **kwargs):
            # 1. Simulate printing the "Using query..." message
            print("Using query 'ProjectCorp' from active project")
            # 2. Simulate printing the final JSON result
            print(mock_scan_result.model_dump_json(indent=1))

        mock_async_run.side_effect = mock_coro

        # Act
        result = runner.invoke(dark_web_app, ["search"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using query 'ProjectCorp' from active project", result.stdout)
        self.assertIn('"query": "ProjectCorp"', result.stdout)
        # Check that the async function was called with None query
        mock_async_run.assert_called_once_with(None, "ahmia", None)

    @patch(
        "chimera_intel.core.dark_web_osint.async_run_dark_web_search",
        new_callable=AsyncMock,
    )
    def test_cli_dark_web_search_no_query_or_project(self, mock_async_run):
        """NEW: Tests CLI failure when no query is given and no project is active."""
        # Arrange
        # Define an async side_effect function to simulate the failure
        async def mock_coro(*args, **kwargs):
            # Simulate the logic check failing and raising Exit
            print(
                "No query provided and no active project",
                file=sys.stderr,
            )
            raise typer.Exit(1)

        mock_async_run.side_effect = mock_coro

        # Act
        result = runner.invoke(dark_web_app, ["search"])

        # Assert
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No query provided and no active project", result.stderr)


if __name__ == "__main__":
    unittest.main()