"""
Unit tests for the 'business_intel' module.
"""

import unittest
from unittest.mock import patch, MagicMock
from httpx import RequestError, HTTPStatusError, Response
from typer.testing import CliRunner
from chimera_intel.cli import app  # Import the main Typer app
from chimera_intel.core.business_intel import (
    get_financials_yfinance,
    get_news_gnews,
    scrape_google_patents,
)
from chimera_intel.core.schemas import Financials, GNewsResult, PatentResult

runner = CliRunner()


class TestBusinessIntel(unittest.TestCase):
    """Test cases for business intelligence gathering functions."""

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_success(self, mock_ticker: MagicMock):
        """
        Tests a successful financial data lookup using the yfinance library.
        """
        mock_instance = mock_ticker.return_value
        mock_instance.info = {
            "longName": "Apple Inc.",
            "marketCap": 2000000000000,
            "trailingPE": 30.5,
            "forwardPE": 25.2,
            "dividendYield": 0.005,
            "sector": "Technology",
        }

        result = get_financials_yfinance("AAPL")
        self.assertIsInstance(result, Financials)
        self.assertEqual(result.companyName, "Apple Inc.")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_invalid_ticker(self, mock_ticker: MagicMock):
        """
        Tests yfinance when an invalid ticker is provided, returning incomplete data.
        """
        mock_instance = mock_ticker.return_value
        mock_instance.info = {"longName": "Invalid Ticker Inc."}
        result = get_financials_yfinance("INVALIDTICKER")
        self.assertIsInstance(result, Financials)
        self.assertIsNotNone(result.error)
        self.assertIn("Could not fetch data", result.error)

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_unexpected_exception(self, mock_ticker: MagicMock):
        """
        Tests yfinance when the library raises an unexpected exception.
        """
        mock_ticker.side_effect = Exception("A critical yfinance error")
        result = get_financials_yfinance("AAPL")
        self.assertIsInstance(result, Financials)
        self.assertIsNotNone(result.error)
        self.assertIn("An unexpected error occurred", result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_get_news_gnews_success(self, mock_get: MagicMock):
        """
        Tests a successful news retrieval from the GNews API.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "totalArticles": 1,
            "articles": [
                {
                    "title": "Test News",
                    "description": "A test description.",
                    "url": "http://test.com/news",
                    "source": {"name": "Test Source"},
                }
            ],
        }
        mock_get.return_value = mock_response

        result = get_news_gnews("Apple Inc.", "fake_api_key")
        self.assertIsInstance(result, GNewsResult)
        self.assertIsNotNone(result.articles)
        self.assertEqual(len(result.articles), 1)

    def test_get_news_gnews_no_api_key(self):
        """Tests GNews retrieval when the API key is missing."""
        result = get_news_gnews("Test Query", "")
        self.assertIsInstance(result, GNewsResult)
        self.assertIsNotNone(result.error)
        self.assertIn("API key not found", result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_get_news_gnews_http_error(self, mock_get: MagicMock):
        """Tests GNews retrieval when an HTTP error occurs."""
        mock_response = MagicMock()
        http_error = HTTPStatusError(
            "Server Error", request=MagicMock(), response=Response(status_code=503)
        )
        mock_response.raise_for_status.side_effect = http_error
        mock_get.return_value = mock_response

        result = get_news_gnews("Test Query", "fake_api_key")
        self.assertIsInstance(result, GNewsResult)
        self.assertIsNotNone(result.error)
        self.assertIn("503", result.error)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_scrape_google_patents_success(self, mock_get: MagicMock):
        """
        Tests a successful web scrape of Google Patents.
        """
        mock_html = """
        <article class="search-result">
            <a class="abs-url" href="/patent/US123/en"></a>
            <h4 class="title">Test Patent Title</h4>
        </article>
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = mock_html
        mock_get.return_value = mock_response

        result = scrape_google_patents("Apple Inc.")
        self.assertIsInstance(result, PatentResult)
        self.assertIsNotNone(result.patents)
        self.assertEqual(len(result.patents), 1)
        self.assertEqual(result.patents[0].title, "Test Patent Title")

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_scrape_google_patents_no_results(self, mock_get: MagicMock):
        """
        Tests patent scraping when the page returns no matching elements.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>No patents here.</body></html>"
        mock_get.return_value = mock_response

        result = scrape_google_patents("A company with no patents")
        self.assertIsInstance(result, PatentResult)
        self.assertIsNotNone(result.patents)
        self.assertEqual(len(result.patents), 0)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_scrape_google_patents_network_error(self, mock_get: MagicMock):
        """
        Tests patent scraping during a network error.
        """
        mock_get.side_effect = RequestError("Connection failed")
        result = scrape_google_patents("Test company")
        self.assertIsInstance(result, PatentResult)
        self.assertIsNotNone(result.error)
        self.assertIn("Network error", result.error)

    # --- NEW TESTS FOR CLI COMMANDS ---

    @patch("chimera_intel.core.business_intel.get_financials_yfinance")
    @patch("chimera_intel.core.business_intel.get_news_gnews")
    @patch("chimera_intel.core.business_intel.scrape_google_patents")
    @patch("chimera_intel.core.config_loader.API_KEYS.gnews_api_key", "fake_key")
    def test_cli_business_intel_with_ticker(
        self, mock_patents, mock_news, mock_financials
    ):
        """Tests the 'business' command when a ticker is provided."""
        result = runner.invoke(
            app, ["scan", "business", "run", "Apple Inc.", "--ticker", "AAPL"]
        )
        self.assertEqual(result.exit_code, 0)
        mock_financials.assert_called_once_with("AAPL")
        mock_news.assert_called_once()
        mock_patents.assert_called_once()

    @patch("chimera_intel.core.business_intel.get_financials_yfinance")
    @patch("chimera_intel.core.business_intel.get_news_gnews")
    @patch("chimera_intel.core.business_intel.scrape_google_patents")
    @patch("chimera_intel.core.config_loader.API_KEYS.gnews_api_key", None)
    def test_cli_business_intel_no_api_key(
        self, mock_patents, mock_news, mock_financials
    ):
        """Tests the 'business' command when the GNews API key is missing."""
        # Mocks to prevent actual calls

        mock_patents.return_value = PatentResult(patents=[])
        mock_financials.return_value = Financials()

        result = runner.invoke(app, ["scan", "business", "run", "Some Company"])
        self.assertEqual(result.exit_code, 0)
        # get_news_gnews should not be called

        mock_news.assert_not_called()
        self.assertIn("GNews API key not configured", result.stdout)


if __name__ == "__main__":
    unittest.main()
