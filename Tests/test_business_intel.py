import unittest
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
)

# CliRunner to simulate CLI commands


runner = CliRunner()


class TestBusinessIntel(unittest.TestCase):
    """Test cases for business intelligence scanning functions."""

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_success(self, mock_ticker):
        """Tests a successful financial data lookup."""
        mock_instance = mock_ticker.return_value
        mock_instance.info = {
            "longName": "Apple Inc.",
            "sector": "Technology",
            "marketCap": 2000000000000,
            "trailingPE": 25.0,
            "forwardPE": 22.0,
            "dividendYield": 0.01,
        }
        result = get_financials_yfinance("AAPL")
        self.assertIsInstance(result, Financials)
        self.assertEqual(result.companyName, "Apple Inc.")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_incomplete_data(self, mock_ticker):
        """Tests yfinance lookup when the API returns incomplete data."""
        mock_instance = mock_ticker.return_value
        # Simulate a response that is missing a key field

        mock_instance.info = {"longName": "Incomplete Inc."}
        result = get_financials_yfinance("INCOMPLETE")
        self.assertIsNotNone(result.error)
        self.assertIn("Could not fetch data", result.error)

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_unexpected_exception(self, mock_ticker):
        """Tests yfinance lookup when an unexpected exception occurs."""
        mock_ticker.side_effect = Exception("A critical error occurred")
        result = get_financials_yfinance("AAPL")
        self.assertIsNotNone(result.error)
        self.assertIn("An unexpected error occurred", result.error)

    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_get_news_gnews_success(self, mock_async_get):
        """Tests a successful news lookup from GNews."""
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "totalArticles": 1,
            "articles": [{"title": "Test News"}],
        }
        mock_async_get.return_value = mock_response
        result = await get_news_gnews("Apple", "fake_api_key")
        self.assertIsInstance(result, GNewsResult)
        self.assertEqual(result.totalArticles, 1)

    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_get_news_gnews_http_error(self, mock_async_get):
        """Tests the GNews lookup when an HTTP error occurs."""
        http_error = HTTPStatusError(
            "Server Error", request=MagicMock(), response=Response(status_code=500)
        )
        mock_async_get.side_effect = http_error
        result = await get_news_gnews("Apple", "fake_api_key")
        self.assertIsNotNone(result.error)
        self.assertIn("500", result.error)

    async def test_get_news_gnews_no_api_key(self):
        """Tests the GNews lookup when the API key is missing."""
        result = await get_news_gnews("Apple", "")
        self.assertIsNotNone(result.error)
        self.assertIn("GNews API key not found", result.error)

    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_scrape_google_patents_success(self, mock_async_get):
        """Tests a successful scrape of Google Patents."""
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
        result = await scrape_google_patents("Apple")
        self.assertIsInstance(result, PatentResult)
        self.assertEqual(len(result.patents), 1)
        self.assertEqual(result.patents[0].title, "Test Patent")

    @patch("chimera_intel.core.business_intel.async_client.get", new_callable=AsyncMock)
    async def test_scrape_google_patents_network_error(self, mock_async_get):
        """Tests the patent scraper when a network error occurs."""
        mock_async_get.side_effect = RequestError("Network down")
        result = await scrape_google_patents("Apple")
        self.assertIsNotNone(result.error)
        self.assertIn("Network error scraping patents", result.error)

    @patch("chimera_intel.core.business_intel.QueryApi")
    @patch("chimera_intel.core.business_intel.ExtractorApi")
    @patch("chimera_intel.core.business_intel.API_KEYS")
    def test_get_sec_filings_analysis_api_exception(
        self, mock_api_keys, mock_extractor_api, mock_query_api
    ):
        """Tests SEC filing analysis when the sec-api library raises an exception."""
        mock_api_keys.sec_api_io_key = "fake_key"
        mock_query_api.side_effect = Exception("SEC API limit reached")
        result = get_sec_filings_analysis("AAPL")
        self.assertIsNotNone(result.error)
        self.assertIn("SEC API limit reached", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.business_intel.asyncio.run")
    def test_cli_business_intel_run_success(self, mock_asyncio_run):
        """Tests a successful run of the 'scan business run' command."""
        result = runner.invoke(business_app, ["Apple", "--ticker", "AAPL"])
        self.assertEqual(result.exit_code, 0)
        mock_asyncio_run.assert_called_once()

    @patch("chimera_intel.core.business_intel.asyncio.run")
    def test_cli_business_intel_with_filings(self, mock_asyncio_run):
        """Tests the CLI command with the --filings flag."""
        result = runner.invoke(
            business_app, ["Microsoft", "--ticker", "MSFT", "--filings"]
        )
        self.assertEqual(result.exit_code, 0)

    @patch("chimera_intel.core.business_intel.API_KEYS")
    @patch("chimera_intel.core.business_intel.logger")
    def test_cli_business_intel_filings_no_ticker(self, mock_logger, mock_api_keys):
        """Tests that a warning is logged if --filings is used without --ticker."""
        mock_api_keys.gnews_api_key = "fake_gnews_key_for_test"

        runner.invoke(business_app, ["Company", "--filings"])

        mock_logger.warning.assert_called_with(
            "The --filings flag requires a --ticker to be provided."
        )

    @patch("chimera_intel.core.business_intel.resolve_target")
    @patch("chimera_intel.core.business_intel.get_active_project")
    @patch("chimera_intel.core.business_intel.asyncio.run")
    def test_cli_business_intel_with_project(
        self, mock_asyncio_run, mock_get_project, mock_resolve_target
    ):
        """Tests the CLI command using the centralized resolver."""
        mock_resolve_target.return_value = "ProjectCorp"
        mock_project = ProjectConfig(project_name="Test", created_at="", ticker="PCRP")
        mock_get_project.return_value = mock_project

        result = runner.invoke(business_app, [])

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_once_with(
            None, required_assets=["company_name"]
        )
        mock_asyncio_run.assert_called_once()

    @patch("chimera_intel.core.business_intel.resolve_target")
    def test_cli_business_intel_resolver_fails(self, mock_resolve_target):
        """Tests the CLI command when the resolver raises an exit exception."""
        mock_resolve_target.side_effect = typer.Exit(code=1)
        result = runner.invoke(business_app, [])
        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
