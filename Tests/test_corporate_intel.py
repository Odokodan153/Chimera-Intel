import unittest
from unittest.mock import patch, MagicMock
from httpx import Response
from typer.testing import CliRunner

from chimera_intel.core.corporate_intel import (
    get_hiring_trends,
    get_employee_sentiment,
    get_trade_data,
    get_trademarks,
    get_lobbying_data,
    get_sec_filings_analysis,
    corporate_intel_app,
)
from chimera_intel.core.schemas import (
    ProjectConfig,
    HiringTrendsResult,
    EmployeeSentimentResult,
)

runner = CliRunner()


class TestCorporateIntel(unittest.TestCase):
    """Test cases for the corporate_intel module."""

    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_hiring_trends(self, mock_get):
        """Tests the hiring trends analysis function."""
        mock_html = '<html><body><a href="/jobs/1">Senior Engineer</a><a href="/jobs/2">Sales Manager</a></body></html>'
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = mock_html
        mock_get.return_value = mock_response

        result = get_hiring_trends("example.com")

        self.assertIsNotNone(result)
        self.assertGreater(result.total_postings, 0)

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_employee_sentiment(self, mock_get, mock_api_keys):
        """Tests the employee sentiment analysis."""
        mock_api_keys.aura_api_key = "fake_aura_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "overall_rating": 4.5,
            "ceo_approval_percentage": 95,
        }
        mock_get.return_value = mock_response

        result = get_employee_sentiment("Example Corp")
        self.assertIsNotNone(result)
        self.assertGreater(result.overall_rating, 0)

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_trade_data(self, mock_get, mock_api_keys):
        """Tests the trade data retrieval."""
        mock_api_keys.import_genius_api_key = "fake_ig_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"total_results": 1, "shipments": []}
        mock_get.return_value = mock_response

        result = get_trade_data("Example Corp")
        self.assertIsNotNone(result)
        self.assertEqual(result.total_shipments, 1)

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_trademarks(self, mock_get, mock_api_keys):
        """Tests the trademark search."""
        mock_api_keys.uspto_api_key = "fake_uspto_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = [{"serial_number": "123"}]
        mock_get.return_value = mock_response

        result = get_trademarks("Example Corp")
        self.assertIsNotNone(result)
        self.assertEqual(result.total_found, 1)

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_lobbying_data(self, mock_get, mock_api_keys):
        """Tests the lobbying data analysis."""
        mock_api_keys.lobbying_data_api_key = "fake_lobby_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [
                {
                    "lobbying_represents": [
                        {
                            "amount": "50000",
                            "specific_issue": "Issue 1",
                            "year": "2023",
                        },
                        {
                            "amount": "25000",
                            "specific_issue": "Issue 2",
                            "year": "2023",
                        },
                    ]
                }
            ]
        }
        mock_get.return_value = mock_response

        result = get_lobbying_data("Example Corp")
        self.assertIsNotNone(result)
        self.assertGreater(result.total_spent, 0)

    @patch("chimera_intel.core.corporate_intel.QueryApi")
    @patch("chimera_intel.core.corporate_intel.ExtractorApi")
    def test_get_sec_filings_analysis_success(self, mock_extractor_api, mock_query_api):
        """Tests a successful SEC filing analysis."""
        mock_query_instance = mock_query_api.return_value
        mock_extractor_instance = mock_extractor_api.return_value
        mock_query_instance.get_filings.return_value = {
            "filings": [{"linkToFilingDetails": "http://fake-url.com"}]
        }
        mock_extractor_instance.get_section.return_value = "Risk factors summary"

        with patch(
            "chimera_intel.core.corporate_intel.API_KEYS.sec_api_io_key", "fake_key"
        ):
            result = get_sec_filings_analysis("AAPL")
        self.assertIsNotNone(result)
        self.assertIn("Risk factors", result.risk_factors_summary)

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
        mock_hiring.return_value = HiringTrendsResult(total_postings=0)
        mock_sentiment.return_value = EmployeeSentimentResult()

        result = runner.invoke(corporate_intel_app, ["hr-intel"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using target 'ProjectCorp' from active project", result.stdout)
        mock_hiring.assert_called_with("project.com")
        mock_sentiment.assert_called_with("ProjectCorp")


if __name__ == "__main__":
    unittest.main()
