import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError
from typer.testing import CliRunner
import os

# Import the main CLI app and the functions to be tested

from chimera_intel.cli import app
from chimera_intel.core.corporate_intel import (
    get_hiring_trends,
    get_employee_sentiment,
    get_trade_data,
    get_trademarks,
    get_lobbying_data,
    get_sec_filings_analysis,
)
from chimera_intel.core.schemas import ProjectConfig
from chimera_intel.core.logger_config import setup_logging

runner = CliRunner()


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
        """Tests the lobbying data analysis by mocking the ProPublica API."""
        # Arrange

        mock_api_keys.lobbying_data_api_key = "fake_lobby_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [
                {
                    "lobbying_represents": [
                        {
                            "specific_issue": "Artificial Intelligence Regulation",
                            "amount": "500000",
                            "year": "2025",
                        }
                    ]
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

    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_hiring_trends_scrape_fails(self, mock_get):
        """Tests that hiring trends gracefully fails when scraping errors out."""
        mock_get.side_effect = RequestError("Failed to connect")
        result = get_hiring_trends("example.com")
        self.assertIsNotNone(result.error)

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    def test_get_employee_sentiment_no_api_key(self, mock_api_keys):
        """Tests that get_employee_sentiment returns an error when the API key is missing."""
        mock_api_keys.aura_api_key = None
        result = get_employee_sentiment("Example Corp")
        self.assertIsNotNone(result.error)

    # --- NEW: Project-Aware CLI Command Tests ---

    @patch("chimera_intel.core.corporate_intel.get_active_project")
    @patch("chimera_intel.core.corporate_intel.get_hiring_trends")
    @patch("chimera_intel.core.corporate_intel.get_employee_sentiment")
    def test_cli_hr_intel_with_project(
        self, mock_sentiment, mock_hiring, mock_get_project
    ):
        """Tests the 'corporate hr-intel' command using an active project."""
        mock_project = ProjectConfig(
            project_name="Test",
            created_at="",
            company_name="ProjectCorp",
            domain="project.com",
        )
        mock_get_project.return_value = mock_project
        mock_hiring.return_value.model_dump.return_value = {}
        mock_sentiment.return_value.model_dump.return_value = {}

        result = runner.invoke(app, ["corporate", "hr-intel"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using target 'ProjectCorp' from active project", result.stdout)
        mock_hiring.assert_called_with("project.com")
        mock_sentiment.assert_called_with("ProjectCorp")

    @patch("chimera_intel.core.corporate_intel.get_active_project")
    def test_cli_sec_filings_no_project(self, mock_get_project):
        """Tests that 'sec-filings' fails without a ticker or project."""
        mock_get_project.return_value = None
        result = runner.invoke(app, ["corporate", "sec-filings"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No ticker provided and no active project", result.stdout)

    @patch("chimera_intel.core.corporate_intel.get_active_project")
    @patch("chimera_intel.core.corporate_intel.get_sec_filings_analysis")
    def test_cli_sec_filings_with_project(self, mock_sec_filings, mock_get_project):
        """Tests the 'sec-filings' command using a project's ticker."""
        mock_project = ProjectConfig(project_name="Test", created_at="", ticker="PRJT")
        mock_get_project.return_value = mock_project
        mock_sec_filings.return_value.model_dump.return_value = {}

        result = runner.invoke(app, ["corporate", "sec-filings"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using ticker 'PRJT' from active project", result.stdout)
        mock_sec_filings.assert_called_with("PRJT")

    @patch("chimera_intel.core.business_intel.API_KEYS")
    def test_cli_business_intel_filings_no_ticker(self, mock_api_keys):
        """Tests that a warning is logged if --filings is used without --ticker."""
        setup_logging()  # Ensure log file is created
        mock_api_keys.gnews_api_key = "fake_gnews_key_for_test"
        log_file = "chimera_intel.log"
        if os.path.exists(log_file):
            os.remove(log_file)
        runner.invoke(app, ["scan", "business", "run", "Company", "--filings"])

        with open(log_file, "r") as f:
            log_content = f.read()
        self.assertIn(
            "The --filings flag requires a --ticker to be provided.", log_content
        )


if __name__ == "__main__":
    unittest.main()
