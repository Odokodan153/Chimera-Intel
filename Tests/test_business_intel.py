import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import RequestError, HTTPStatusError, Response
from typer.testing import CliRunner
import typer

# Import the specific Typer app for this module
from chimera_intel.core.business_intel import (
    get_financials_yfinance,
    get_news_gnews,
    scrape_google_patents,
    get_sec_filings_analysis,
    business_app,  # Import the specific app
)

# Import all necessary Pydantic models for testing
from chimera_intel.core.schemas import (
    Financials,
    GNewsResult,
    PatentResult,
    ProjectConfig,
    SECFilingAnalysis,
)

# CliRunner to simulate CLI commands
runner = CliRunner()


def run_coroutine(coro):
    """Helper function to run a coroutine in tests."""
    # This helper is useful again for our side_effect
    return asyncio.get_event_loop().run_until_complete(coro)


class TestBusinessIntel(unittest.IsolatedAsyncioTestCase):
    """Test cases for business intelligence scanning functions."""

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_success(self, mock_ticker):
        """Tests a successful financial data lookup."""
        # Arrange
        mock_instance = mock_ticker.return_value
        mock_instance.info = {
            "longName": "Apple Inc.",
            "sector": "Technology",
            "marketCap": 2000000000000,
            "trailingPE": 25.0,
            "forwardPE": 22.0,
            "dividendYield": 0.01,
        }

        # Act
        result = get_financials_yfinance("AAPL")

        # Assert
        self.assertIsInstance(result, Financials)
        self.assertEqual(result.companyName, "Apple Inc.")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_incomplete_data(self, mock_ticker):
        """Tests yfinance lookup when the API returns incomplete data."""
        # Arrange
        mock_instance = mock_ticker.return_value
        # Simulate a response that is missing a key field like 'trailingPE'
        mock_instance.info = {"longName": "Incomplete Inc."}

        # Act
        result = get_financials_yfinance("INCOMPLETE")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("Could not fetch data", result.error)

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_unexpected_exception(self, mock_ticker):
        """Tests yfinance lookup when an unexpected exception occurs."""
        # Arrange
        mock_ticker.side_effect = Exception("A critical error occurred")

        # Act
        result = get_financials_yfinance("AAPL")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("An unexpected error occurred", result.error)

    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_get_news_gnews_success(self, mock_async_get):
        """Tests a successful news lookup from GNews."""
        # Arrange
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "totalArticles": 1,
            "articles": [
                {"title": "Test News", "description": "...", "url": "...", "source": {}}
            ],
        }
        mock_async_get.return_value = mock_response

        # Act
        result = await get_news_gnews("Apple", "fake_api_key")

        # Assert
        self.assertIsInstance(result, GNewsResult)
        self.assertEqual(result.totalArticles, 1)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_get_news_gnews_http_error(self, mock_async_get):
        """Tests the GNews lookup when an HTTP error occurs."""
        # Arrange
        http_error = HTTPStatusError(
            "Server Error", request=MagicMock(), response=Response(status_code=500)
        )
        mock_async_get.side_effect = http_error

        # Act
        result = await get_news_gnews("Apple", "fake_api_key")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("500", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_get_news_gnews_request_error(self, mock_async_get):
        """Tests the GNews lookup for a network/request error."""
        # Arrange
        mock_async_get.side_effect = RequestError("Network down")

        # Act
        result = await get_news_gnews("Apple", "fake_api_key")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("A network error occurred: Network down", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_get_news_gnews_unexpected_error(self, mock_async_get):
        """Tests the GNews lookup for a generic exception."""
        # Arrange
        mock_async_get.side_effect = Exception("Parsing error")

        # Act
        result = await get_news_gnews("Apple", "fake_api_key")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("An unexpected error occurred: Parsing error", result.error)

    async def test_get_news_gnews_no_api_key(self):
        """Tests the GNews lookup when the API key is missing."""
        # Act
        result = await get_news_gnews("Apple", "")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("GNews API key not found", result.error)

    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_scrape_google_patents_success(self, mock_async_get):
        """Tests a successful scrape of Google Patents."""
        # Arrange
        mock_html = """
        <article class="search-result">
            <h4 class="title">Test Patent</h4>
            <a class="abs-url" href="/patent/US123/en"></a>
        </article>
        """
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.text = mock_html
        mock_async_get.return_value = mock_response

        # Act
        result = await scrape_google_patents("Apple")

        # Assert
        self.assertIsInstance(result, PatentResult)
        self.assertEqual(len(result.patents), 1)
        self.assertEqual(result.patents[0].title, "Test Patent")

    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_scrape_google_patents_network_error(self, mock_async_get):
        """Tests the patent scraper when a network error occurs."""
        # Arrange
        mock_async_get.side_effect = RequestError("Network down")

        # Act
        result = await scrape_google_patents("Apple")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("Network error scraping patents", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_scrape_google_patents_http_error(self, mock_async_get):
        """Tests the patent scraper for an HTTP status error."""
        # Arrange
        http_error = HTTPStatusError(
            "Forbidden", request=MagicMock(), response=Response(status_code=403)
        )
        mock_async_get.side_effect = http_error

        # Act
        result = await scrape_google_patents("Apple")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("HTTP error scraping patents: 403", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_scrape_google_patents_unexpected_error(self, mock_async_get):
        """Tests the patent scraper for a generic exception."""
        # Arrange
        mock_async_get.side_effect = Exception("Parsing error")

        # Act
        result = await scrape_google_patents("Apple")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("An unexpected error occurred while scraping patents", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.business_intel.API_KEYS")
    def test_get_sec_filings_analysis_no_api_key(self, mock_api_keys):
        """Tests SEC filing analysis when the sec-api key is missing."""
        # Arrange
        mock_api_keys.sec_api_io_key = None

        # Act
        result = get_sec_filings_analysis("AAPL")

        # Assert
        self.assertIsNone(result)

    # --- Extended Test ---
    @patch("chimera_intel.core.business_intel.QueryApi")
    @patch("chimera_intel.core.business_intel.API_KEYS")
    def test_get_sec_filings_analysis_no_filings_found(
        self, mock_api_keys, mock_query_api
    ):
        """Tests SEC filing analysis when no 10-K filings are found."""
        # Arrange
        mock_api_keys.sec_api_io_key = "fake_key"
        mock_query_instance = mock_query_api.return_value
        # Simulate API returning an empty list of filings
        mock_query_instance.get_filings.return_value = {"filings": []}

        # Act
        result = get_sec_filings_analysis("AAPL")

        # Assert
        self.assertIsNone(result)

    @patch("chimera_intel.core.business_intel.QueryApi")
    @patch("chimera_intel.core.business_intel.ExtractorApi")
    @patch("chimera_intel.core.business_intel.API_KEYS")
    def test_get_sec_filings_analysis_api_exception(
        self, mock_api_keys, mock_extractor_api, mock_query_api
    ):
        """Tests SEC filing analysis when the sec-api library raises an exception."""
        # Arrange
        mock_api_keys.sec_api_io_key = "fake_key"
        mock_query_api.side_effect = Exception("SEC API limit reached")

        # Act
        result = get_sec_filings_analysis("AAPL")

        # Assert
        self.assertIsInstance(result, SECFilingAnalysis)
        self.assertIsNotNone(result.error)
        self.assertIn("SEC API limit reached", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.business_intel.save_or_print_results")
    @patch("chimera_intel.core.business_intel.save_scan_to_db")
    @patch("chimera_intel.core.business_intel.asyncio.run")
    @patch("chimera_intel.core.business_intel.get_active_project", return_value=None)
    @patch("chimera_intel.core.business_intel.resolve_target", return_value="Apple")
    @patch("chimera_intel.core.business_intel.API_KEYS")
    def test_cli_business_intel_run_success(
        self,
        mock_api_keys,
        mock_resolve_target,
        mock_get_project,
        mock_asyncio_run,
        mock_save_db,
        mock_save_print,
    ):
        """Tests a successful run of the 'business run' command."""
        # Arrange
        mock_api_keys.gnews_api_key = "dummy_key"
        mock_asyncio_run.side_effect = run_coroutine

        # Act
        result = runner.invoke(business_app, ["run", "Apple", "--ticker", "AAPL"])

        # Assert
        self.assertEqual(result.exit_code, 0, result.stderr)
        mock_asyncio_run.assert_called_once()
        mock_save_print.assert_called_once()
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.business_intel.save_or_print_results")
    @patch("chimera_intel.core.business_intel.save_scan_to_db")
    @patch("chimera_intel.core.business_intel.asyncio.run")
    @patch("chimera_intel.core.business_intel.get_active_project", return_value=None)
    @patch("chimera_intel.core.business_intel.resolve_target", return_value="Microsoft")
    @patch("chimera_intel.core.business_intel.API_KEYS")
    def test_cli_business_intel_with_filings(
        self,
        mock_api_keys,
        mock_resolve_target,
        mock_get_project,
        mock_asyncio_run,
        mock_save_db,
        mock_save_print,
    ):
        """Tests the CLI command with the --filings flag."""
        # Arrange
        mock_api_keys.gnews_api_key = "dummy_key"
        mock_api_keys.sec_api_io_key = "dummy_key"
        mock_asyncio_run.side_effect = run_coroutine

        # Act
        result = runner.invoke(
            business_app, ["run", "Microsoft", "--ticker", "MSFT", "--filings"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0, result.stderr)
        mock_asyncio_run.assert_called_once()
        mock_save_print.assert_called_once()
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.business_intel.save_or_print_results")
    @patch("chimera_intel.core.business_intel.save_scan_to_db")
    @patch("chimera_intel.core.business_intel.asyncio.run")
    @patch("chimera_intel.core.business_intel.get_active_project", return_value=None)
    @patch("chimera_intel.core.business_intel.resolve_target", return_value="SomeCompany")
    @patch("chimera_intel.core.business_intel.API_KEYS")
    @patch("chimera_intel.core.business_intel.logger")
    def test_cli_business_intel_filings_no_ticker_warning(
        self,
        mock_logger,
        mock_api_keys,
        mock_resolve_target,
        mock_get_project,
        mock_asyncio_run,
        mock_save_db,
        mock_save_print,
    ):
        """Tests that a warning is logged if --filings is used without --ticker."""
        # Arrange
        mock_api_keys.gnews_api_key = "dummy_key"
        mock_asyncio_run.side_effect = run_coroutine

        # Act
        result = runner.invoke(business_app, ["run", "SomeCompany", "--filings"])

        # Assert
        self.assertEqual(result.exit_code, 0, result.stderr)
        mock_logger.warning.assert_called_with(
            "The --filings flag requires a --ticker to be provided."
        )
        mock_asyncio_run.assert_called_once()
        mock_save_print.assert_called_once()
        mock_save_db.assert_called_once()

    # --- Extended Test ---
    @patch("chimera_intel.core.business_intel.save_or_print_results")
    @patch("chimera_intel.core.business_intel.save_scan_to_db")
    @patch("chimera_intel.core.business_intel.asyncio.run")
    @patch("chimera_intel.core.business_intel.get_active_project", return_value=None)
    @patch("chimera_intel.core.business_intel.resolve_target", return_value="SomeCompany")
    @patch("chimera_intel.core.business_intel.API_KEYS")
    @patch("chimera_intel.core.business_intel.logger")
    def test_cli_business_intel_no_gnews_key_warning(
        self,
        mock_logger,
        mock_api_keys,
        mock_resolve_target,
        mock_get_project,
        mock_asyncio_run,
        mock_save_db,
        mock_save_print,
    ):
        """Tests that a warning is logged if the GNews API key is missing."""
        # Arrange
        mock_api_keys.gnews_api_key = None  # No GNews key
        mock_asyncio_run.side_effect = run_coroutine

        # Act
        result = runner.invoke(business_app, ["run", "SomeCompany"])

        # Assert
        self.assertEqual(result.exit_code, 0, result.stderr)
        mock_logger.warning.assert_called_with(
            "GNews API key not found. Skipping news gathering."
        )
        mock_asyncio_run.assert_called_once()
        mock_save_print.assert_called_once()
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.business_intel.save_or_print_results")
    @patch("chimera_intel.core.business_intel.save_scan_to_db")
    @patch("chimera_intel.core.business_intel.resolve_target")
    @patch("chimera_intel.core.business_intel.get_active_project")
    @patch("chimera_intel.core.business_intel.asyncio.run")
    @patch("chimera_intel.core.business_intel.API_KEYS")
    def test_cli_business_intel_with_project_context(
        self,
        mock_api_keys,
        mock_asyncio_run,
        mock_get_project,
        mock_resolve_target,
        mock_save_db,
        mock_save_print,
    ):
        """Tests the CLI command using the centralized resolver with an active project."""
        # Arrange
        mock_api_keys.gnews_api_key = "dummy_key"
        mock_resolve_target.return_value = "ProjectCorp"
        mock_project = ProjectConfig(
            project_name="Test",
            created_at="",
            company_name="ProjectCorp",
            ticker="PCRP",
        )
        mock_get_project.return_value = mock_project
        mock_asyncio_run.side_effect = run_coroutine
        
        # Act
        # This will pass `None` to company_name, triggering the resolver.
        result = runner.invoke(business_app, ["run"])

        # Assert
        self.assertEqual(result.exit_code, 0, result.stderr)
        mock_resolve_target.assert_called_once_with(
            None, required_assets=["company_name"]
        )
        mock_asyncio_run.assert_called_once()
        mock_save_print.assert_called_once()
        mock_save_db.assert_called_once()

    @patch("chimera_intel.core.business_intel.resolve_target")
    def test_cli_business_intel_resolver_fails(self, mock_resolve_target):
        """Tests the CLI command when the resolver raises an exit exception."""
        # Arrange
        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act
        result = runner.invoke(business_app, ["run"])

        # Assert
        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()