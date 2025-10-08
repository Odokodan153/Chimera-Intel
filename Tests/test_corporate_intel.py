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
    TradeDataResult,
    TrademarkResult,
    LobbyingResult,
    SECFilingAnalysis,
)

runner = CliRunner()


class TestCorporateIntel(unittest.TestCase):
    """Test cases for the corporate_intel module."""

    # --- Hiring Trends Tests ---

    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_hiring_trends_success(self, mock_get):
        """Tests the hiring trends analysis function with a successful scrape."""
        mock_html = '<html><body><a href="/jobs/1">Senior Engineer</a><a href="/jobs/2">Sales Manager</a></body></html>'
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = mock_html
        mock_get.return_value = mock_response

        result = get_hiring_trends("example.com")

        self.assertIsInstance(result, HiringTrendsResult)
        self.assertGreater(result.total_postings, 0)
        self.assertIn("Engineering", result.trends_by_department)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_hiring_trends_no_careers_page(self, mock_get):
        """Tests the hiring trends function when no careers page is found."""
        mock_response = MagicMock(spec=Response, status_code=404)
        mock_get.return_value = mock_response

        result = get_hiring_trends("example.com")

        self.assertEqual(result.total_postings, 0)
        self.assertIn("Could not find or parse a careers page", result.error)

    # --- Employee Sentiment Tests ---

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_employee_sentiment_success(self, mock_get, mock_api_keys):
        """Tests the employee sentiment analysis with a successful API call."""
        mock_api_keys.aura_api_key = "fake_aura_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "overall_rating": 4.5,
            "ceo_approval_percentage": 95,
        }
        mock_get.return_value = mock_response

        result = get_employee_sentiment("Example Corp")

        self.assertIsInstance(result, EmployeeSentimentResult)
        self.assertEqual(result.overall_rating, 4.5)
        self.assertIsNone(result.error)

    def test_get_employee_sentiment_no_api_key(self):
        """Tests employee sentiment analysis when the API key is missing."""
        with patch("chimera_intel.core.corporate_intel.API_KEYS.aura_api_key", None):
            result = get_employee_sentiment("Example Corp")
            self.assertIsNotNone(result.error)
            self.assertIn("Aura Intelligence API key not found", result.error)

    # --- Trade Data Tests ---

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_trade_data_success(self, mock_get, mock_api_keys):
        """Tests the trade data retrieval with a successful API call."""
        mock_api_keys.import_genius_api_key = "fake_ig_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"total_results": 1, "shipments": []}
        mock_get.return_value = mock_response

        result = get_trade_data("Example Corp")

        self.assertIsInstance(result, TradeDataResult)
        self.assertEqual(result.total_shipments, 1)
        self.assertIsNone(result.error)

    # --- Trademark Tests ---

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_trademarks_success(self, mock_get, mock_api_keys):
        """Tests the trademark search with a successful API call."""
        mock_api_keys.uspto_api_key = "fake_uspto_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = [{"serial_number": "123"}]
        mock_get.return_value = mock_response

        result = get_trademarks("Example Corp")
        self.assertIsInstance(result, TrademarkResult)
        self.assertEqual(result.total_found, 1)
        self.assertIsNone(result.error)

    # --- Lobbying Data Tests ---

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_lobbying_data_success(self, mock_get, mock_api_keys):
        """Tests the lobbying data analysis with a successful API call."""
        mock_api_keys.lobbying_data_api_key = "fake_lobby_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [{"lobbying_represents": [{"amount": "50000", "year": "2023"}]}]
        }
        mock_get.return_value = mock_response

        result = get_lobbying_data("Example Corp")

        self.assertIsInstance(result, LobbyingResult)
        self.assertEqual(result.total_spent, 50000)
        self.assertIsNone(result.error)

    # --- SEC Filings Tests ---

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
        self.assertIsInstance(result, SECFilingAnalysis)
        self.assertIn("Risk factors", result.risk_factors_summary)
        self.assertIsNone(result.error)

    # --- CLI Command Tests ---

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
        mock_hiring.return_value = HiringTrendsResult(total_postings=5)
        mock_sentiment.return_value = EmployeeSentimentResult(overall_rating=4.0)

        result = runner.invoke(corporate_intel_app, ["hr-intel"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using target 'ProjectCorp' from active project", result.stdout)
        mock_hiring.assert_called_with("project.com")
        mock_sentiment.assert_called_with("ProjectCorp")

    @patch("chimera_intel.core.corporate_intel.get_trade_data")
    def test_cli_supplychain_with_argument(self, mock_get_trade):
        """NEW: Tests the 'corporate supplychain' command with a direct argument."""
        mock_get_trade.return_value = TradeDataResult(total_shipments=10)

        result = runner.invoke(corporate_intel_app, ["supplychain", "Test Company"])

        self.assertEqual(result.exit_code, 0)
        mock_get_trade.assert_called_with("Test Company")
        self.assertIn('"total_shipments": 10', result.stdout)

    @patch("chimera_intel.core.corporate_intel.get_active_project")
    def test_cli_command_no_target_or_project(self, mock_get_project):
        """NEW: Tests any command fails when no target is given and no project is active."""
        mock_get_project.return_value = None

        result = runner.invoke(corporate_intel_app, ["ip-deep"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No company name provided and no active project", result.stdout)


if __name__ == "__main__":
    unittest.main()
