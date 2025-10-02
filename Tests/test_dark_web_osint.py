import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import Response, RequestError
from typer.testing import CliRunner

# Corrected: Import the specific Typer app for this module


from chimera_intel.core.dark_web_osint import dark_web_app, search_dark_web_engine
from chimera_intel.core.schemas import ProjectConfig

runner = CliRunner(mix_stderr=False)


class TestDarkWebOsint(unittest.TestCase):
    """Test cases for the dark_web_osint module."""

    @patch("chimera_intel.core.dark_web_osint.CONFIG")
    @patch("chimera_intel.core.dark_web_osint.httpx.AsyncClient")
    def test_search_ahmia_success(self, mock_async_client_constructor, mock_config):
        """Tests a successful dark web search on Ahmia."""
        mock_config.modules.dark_web.tor_proxy_url = "socks5://fake.proxy:9999"
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = """
        <li class="result">
          <a>Test Title</a>
          <cite>http://test.onion</cite>
          <p>Test Description</p>
        </li>
        """
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_async_client_constructor.return_value.__aenter__.return_value = mock_client

        result = asyncio.run(search_dark_web_engine("test query", engine="ahmia"))

        self.assertEqual(len(result.found_results), 1)
        self.assertEqual(result.found_results[0].title, "Test Title")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.dark_web_osint.CONFIG")
    @patch("chimera_intel.core.dark_web_osint.httpx.AsyncClient")
    def test_search_darksearch_success(
        self, mock_async_client_constructor, mock_config
    ):
        """Tests a successful dark web search on Dark Search."""
        mock_config.modules.dark_web.tor_proxy_url = "socks5://fake.proxy:9999"
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = """
        <div class="card-body">
          <h5>
            <a href="#">Dark Search Title</a>
            <small>http://darksearch.onion</small>
          </h5>
          <p class="text-break">Dark Search Description</p>
        </div>
        """
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_async_client_constructor.return_value.__aenter__.return_value = mock_client

        result = asyncio.run(search_dark_web_engine("test query", engine="darksearch"))

        self.assertEqual(len(result.found_results), 1)
        self.assertEqual(result.found_results[0].title, "Dark Search Title")
        self.assertEqual(result.found_results[0].url, "http://darksearch.onion")
        self.assertEqual(result.found_results[0].description, "Dark Search Description")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.dark_web_osint.CONFIG")
    @patch("chimera_intel.core.dark_web_osint.httpx.AsyncClient")
    def test_search_dark_web_timeout(self, mock_async_client_constructor, mock_config):
        """Tests the dark web search when a timeout occurs."""
        mock_config.modules.dark_web.tor_proxy_url = "socks5://fake.proxy:9999"
        mock_client = AsyncMock()
        mock_client.get.side_effect = asyncio.TimeoutError
        mock_async_client_constructor.return_value.__aenter__.return_value = mock_client

        result = asyncio.run(search_dark_web_engine("test query"))

        self.assertEqual(len(result.found_results), 0)
        self.assertIsNotNone(result.error)
        self.assertIn("timed out", result.error)

    @patch("chimera_intel.core.dark_web_osint.CONFIG")
    @patch("chimera_intel.core.dark_web_osint.httpx.AsyncClient")
    def test_search_dark_web_generic_exception(
        self, mock_async_client_constructor, mock_config
    ):
        """Tests the dark web search when a generic exception occurs."""
        mock_config.modules.dark_web.tor_proxy_url = "socks5://fake.proxy:9999"
        mock_client = AsyncMock()
        mock_client.get.side_effect = RequestError("Proxy error")
        mock_async_client_constructor.return_value.__aenter__.return_value = mock_client

        result = asyncio.run(search_dark_web_engine("test query"))

        self.assertEqual(len(result.found_results), 0)
        self.assertIsNotNone(result.error)
        self.assertIn("Is the Tor Browser running?", result.error)

    # --- NEW: Project-Aware CLI Tests ---

    @patch("chimera_intel.core.dark_web_osint.get_active_project")
    @patch(
        "chimera_intel.core.dark_web_osint.search_dark_web_engine",
        new_callable=AsyncMock,
    )
    @patch("chimera_intel.core.dark_web_osint.save_scan_to_db")
    def test_cli_dark_web_with_project(
        self, mock_save_db, mock_search_engine, mock_get_project
    ):
        """Tests the CLI command using an active project's company name as the query."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="DarkWebTest",
            created_at="2025-01-01",
            company_name="ProjectCorp",
        )
        mock_get_project.return_value = mock_project
        mock_search_engine.return_value.model_dump.return_value = {}

        # Act
        # FIX: The command being tested is 'search', and when no arguments are given,
        # the runner should be invoked with an empty list.

        result = runner.invoke(dark_web_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using query 'ProjectCorp' from active project", result.stdout)
        mock_search_engine.assert_awaited_with("ProjectCorp", "ahmia")
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.dark_web_osint.get_active_project")
    def test_cli_dark_web_no_query_no_project(self, mock_get_project):
        """Tests CLI failure when no query is given and no project is active."""
        # Arrange

        mock_get_project.return_value = None

        # Act
        # FIX: Correct invocation for a command with an optional argument being omitted.

        result = runner.invoke(dark_web_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No query provided and no active project", result.stdout)


if __name__ == "__main__":
    unittest.main()
