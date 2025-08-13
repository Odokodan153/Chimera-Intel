import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.business_intel import get_financials_yfinance, get_news_gnews, scrape_google_patents

class TestBusinessIntel(unittest.TestCase):

    @patch('chimera_intel.core.business_intel.yf.Ticker')
    def test_get_financials_yfinance_success(self, mock_ticker):
        # Simulate a successful yfinance call
        mock_instance = mock_ticker.return_value
        mock_instance.info = {"longName": "Apple Inc.", "marketCap": 2000000000000}
        result = get_financials_yfinance("AAPL")
        self.assertEqual(result["companyName"], "Apple Inc.")
        self.assertEqual(result["marketCap"], 2000000000000)

    @patch('chimera_intel.core.business_intel.requests.get')
    def test_get_news_gnews_success(self, mock_get):
        # Simulate a successful GNews API call
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"articles": [{"title": "Test News"}]}
        mock_get.return_value = mock_response
        result = get_news_gnews("Apple Inc.", "fake_api_key")
        self.assertEqual(len(result["articles"]), 1)

    @patch('chimera_intel.core.business_intel.requests.get')
    def test_scrape_google_patents_success(self, mock_get):
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
        self.assertEqual(len(result["patents"]), 1)
        self.assertEqual(result["patents"][0]["title"], "Test Patent Title")

if __name__ == '__main__':
    unittest.main()