import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response
from typer.testing import CliRunner
import json

from chimera_intel.core.dark_web_osint import search_dark_web_engine, dark_web_app
from chimera_intel.core.schemas import DarkWebScanResult, DarkWebResult, ProjectConfig

runner = CliRunner()


class TestDarkWebOsint(unittest.IsolatedAsyncioTestCase):
    """Test cases for the dark_web_osint module."""

    @patch("chimera_intel.core.dark_web_osint.CONFIG")
    @patch("httpx_socks.AsyncProxyTransport.from_url")
    async def test_search_dark_web_engine_success(self, mock_transport, mock_config):
        """Tests a successful dark web search using the Ahmia engine."""
        # Arrange

        mock_config.modules.dark_web.tor_proxy_url = "socks5://127.0.0.1:9150"

        mock_async_client = AsyncMock()
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

        with patch("httpx.AsyncClient", return_value=mock_async_client):
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
    @patch("httpx_socks.AsyncProxyTransport.from_url")
    async def test_search_dark_web_engine_timeout(self, mock_transport, mock_config):
        """NEW: Tests the function's timeout handling."""
        # Arrange

        mock_config.modules.dark_web.tor_proxy_url = "socks5://127.0.0.1:9150"

        mock_async_client = AsyncMock()
        mock_async_client.get.side_effect = asyncio.TimeoutError

        with patch("httpx.AsyncClient", return_value=mock_async_client):
            # Act

            result = await search_dark_web_engine("test query")
        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Search timed out", result.error)

    # --- CLI Command Tests ---

    @patch(
        "chimera_intel.core.dark_web_osint.search_dark_web_engine",
        new_callable=AsyncMock,
    )
    def test_cli_dark_web_search_success(self, mock_search):
        """NEW: Tests a successful run of the 'dark-web search' command."""
        # Arrange

        mock_search.return_value = DarkWebScanResult(
            query="testcorp",
            found_results=[DarkWebResult(title="Test Result", url="http://test.onion")],
        )

        # Act

        result = runner.invoke(dark_web_app, ["search", "testcorp"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["query"], "testcorp")
        self.assertEqual(len(output["found_results"]), 1)
        mock_search.assert_awaited_with("testcorp", "ahmia")

    @patch("chimera_intel.core.dark_web_osint.get_active_project")
    @patch(
        "chimera_intel.core.dark_web_osint.search_dark_web_engine",
        new_callable=AsyncMock,
    )
    def test_cli_dark_web_search_with_project(self, mock_search, mock_get_project):
        """NEW: Tests the CLI command using an active project's company name."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="Test", created_at="", company_name="ProjectCorp"
        )
        mock_get_project.return_value = mock_project
        mock_search.return_value = DarkWebScanResult(
            query="ProjectCorp", found_results=[]
        )

        # Act

        result = runner.invoke(dark_web_app, ["search"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using query 'ProjectCorp' from active project", result.stdout)
        mock_search.assert_awaited_with("ProjectCorp", "ahmia")

    @patch("chimera_intel.core.dark_web_osint.get_active_project", return_value=None)
    def test_cli_dark_web_search_no_query_or_project(self, mock_get_project):
        """NEW: Tests CLI failure when no query is given and no project is active."""
        # Act

        result = runner.invoke(dark_web_app, ["search"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No query provided and no active project", result.stdout)


if __name__ == "__main__":
    unittest.main()
