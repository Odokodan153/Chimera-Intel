# tests/test_corporate_intel.py


import unittest
from unittest.mock import patch, MagicMock
from httpx import Response

# Import the functions to be tested


from chimera_intel.core.corporate_intel import (
    get_hiring_trends,
    get_employee_sentiment,
    get_trade_data,
    get_trademarks,
    get_lobbying_data,
    get_sec_filings_analysis,
)

# Import schemas to apply a patch


from chimera_intel.core import schemas


class TestCorporateIntel(unittest.TestCase):
    """Test cases for the corporate_intel module."""

    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_hiring_trends(self, mock_get):
        """Tests the hiring trends analysis function by mocking the web scrape."""
        # Arrange: Simulate a successful scrape of a careers page

        mock_html = '<html><body><a href="/jobs/1">Senior Engineer</a><a href="/jobs/2">Sales Manager</a></body></html>'
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = mock_html
        mock_get.return_value = mock_response

        # Act

        result = get_hiring_trends("example.com")

        # Assert

        self.assertIsNotNone(result)
        self.assertGreater(result.total_postings, 0)
        self.assertIn("Engineering", result.trends_by_department)
        self.assertIn("Sales/Marketing", result.trends_by_department)

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_employee_sentiment(self, mock_get, mock_api_keys):
        """Tests the employee sentiment analysis by mocking the Aura API."""
        # Arrange

        mock_api_keys.aura_api_key = "fake_aura_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "overall_rating": 4.5,
            "ceo_approval_percentage": 95,
            "sentiment_by_category": {"work_life_balance": 3.8},
        }
        mock_get.return_value = mock_response

        # Act

        result = get_employee_sentiment("Example Corp")

        # Assert

        self.assertIsNotNone(result)
        self.assertGreater(result.overall_rating, 0)
        self.assertEqual(result.ceo_approval, "95%")

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_trade_data(self, mock_get, mock_api_keys):
        """Tests the trade data retrieval by mocking the ImportGenius API."""
        # Arrange

        mock_api_keys.import_genius_api_key = "fake_ig_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "total_results": 1,
            "shipments": [
                {
                    "arrival_date": "2025-08-15",
                    "shipper": {"name": "Shenzhen Microchip Corp"},
                    "consignee": {"name": "Example Corp"},
                    "description": "Integrated Circuits",
                }
            ],
        }
        mock_get.return_value = mock_response

        # Act

        result = get_trade_data("Example Corp")

        # Assert

        self.assertIsNotNone(result)
        self.assertEqual(result.total_shipments, 1)
        self.assertIn("Integrated Circuits", result.shipments[0].product_description)

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_trademarks(self, mock_get, mock_api_keys):
        """Tests the trademark search by mocking the USPTO Trademark API."""
        # Arrange

        mock_api_keys.uspto_api_key = "fake_uspto_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = [
            {
                "serial_number": "987654321",
                "status_label": "Live",
                "description": "Project Chimera - A new software product.",
                "owner": {"name": "Example Corp"},
            }
        ]
        mock_get.return_value = mock_response

        # Act

        result = get_trademarks("Example Corp")

        # Assert

        self.assertIsNotNone(result)
        self.assertEqual(result.total_found, 1)
        self.assertIn("Project Chimera", result.trademarks[0].description)

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_lobbying_data(self, mock_get, mock_api_keys):
        """Tests the lobbying data analysis by mocking the LobbyingData.com API."""
        # Arrange

        mock_api_keys.lobbying_data_api_key = "fake_lobby_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "filings": [
                {
                    "specific_issue": "Artificial Intelligence Regulation",
                    "amount": 500000,
                    "year": 2025,
                }
            ]
        }
        mock_get.return_value = mock_response

        # Act

        result = get_lobbying_data("Example Corp")

        # Assert

        self.assertIsNotNone(result)
        self.assertGreater(result.total_spent, 0)
        self.assertEqual(result.records[0].year, 2025)

    @patch("chimera_intel.core.corporate_intel.QueryApi")
    @patch("chimera_intel.core.corporate_intel.ExtractorApi")
    def test_get_sec_filings_analysis_success(self, mock_extractor_api, mock_query_api):
        """Tests a successful SEC filing analysis."""
        # Arrange

        mock_query_instance = mock_query_api.return_value
        mock_extractor_instance = mock_extractor_api.return_value

        mock_query_instance.get_filings.return_value = {
            "filings": [{"linkToFilingDetails": "http://fake-url.com"}]
        }
        mock_extractor_instance.get_section.return_value = (
            "This is a summary of the risk factors."
        )

        # Act

        with patch(
            "chimera_intel.core.corporate_intel.API_KEYS.sec_api_io_key", "fake_key"
        ):
            result = get_sec_filings_analysis("AAPL")
        # Assert

        self.assertIsNotNone(result)
        self.assertIn("risk factors", result.risk_factors_summary)


if __name__ == "__main__":
    unittest.main()
