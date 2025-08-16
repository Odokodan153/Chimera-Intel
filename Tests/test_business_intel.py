"""
Unit tests for the 'business_intel' module.

This test suite verifies the functionality of the business intelligence gathering
functions in 'chimera_intel.core.business_intel.py'. It uses 'unittest.mock'
to simulate responses from external libraries (yfinance) and network calls,
ensuring the tests are fast and reliable.
"""

import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.business_intel import (
    get_financials_yfinance,
    get_news_gnews,
    scrape_google_patents,
)


class TestBusinessIntel(unittest.TestCase):
    """Test cases for business intelligence gathering functions."""

    @patch("chimera_intel.core.business_intel.yf.Ticker")
    def test_get_financials_yfinance_success(self, mock_ticker):
        """
        Tests a successful financial data lookup using the yfinance library.

        This test mocks the 'yf.Ticker' object to simulate a valid response
        without making a real call to Yahoo Finance.
        """
        # Simulate a successful yfinance call

        mock_instance = mock_ticker.return_value
        mock_instance.info = {"longName": "Apple Inc.", "marketCap": 2000000000000}

        result = get_financials_yfinance("AAPL")
        self.assertEqual(result.companyName, "Apple Inc.")
        self.assertEqual(result.marketCap, 2000000000000)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_get_news_gnews_success(self, mock_get):
        """
        Tests a successful news retrieval from the GNews API.

        This test mocks the central 'sync_client.get' method to simulate a
        successful API response with a sample news article.
        """
        # Simulate a successful GNews API call

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "totalArticles": 1,
            "articles": [
                {
                    "title": "Test News",
                    "description": "A test",
                    "url": "http://test.com",
                    "source": {"name": "test"},
                }
            ],
        }
        mock_get.return_value = mock_response

        result = get_news_gnews("Apple Inc.", "fake_api_key")
        self.assertEqual(len(result.articles), 1)

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_scrape_google_patents_success(self, mock_get):
        """
        Tests a successful web scrape of Google Patents.

        This test mocks the central 'sync_client.get' method to return a
        sample HTML snippet, simulating a successful scrape of the patents page.
        """
        # Simulate a successful web scrape

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
        self.assertEqual(len(result.patents), 1)
        self.assertEqual(result.patents[0].title, "Test Patent Title")


if __name__ == "__main__":
    unittest.main()
