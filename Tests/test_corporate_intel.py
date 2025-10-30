import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError
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
    Shipment,
    Trademark,
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

    # NEW: Test for scrape exception (covers line 44)
    @patch(
        "chimera_intel.core.corporate_intel.sync_client.get",
        side_effect=RequestError("Test error"),
    )
    def test_get_hiring_trends_scrape_exception(self, mock_get):
        """Tests the hiring trends function when the scrape fails with an exception."""
        result = get_hiring_trends("example.com")
        self.assertEqual(result.total_postings, 0)
        self.assertIn("Could not find or parse", result.error)
        # Ensures both URLs were tried
        self.assertEqual(mock_get.call_count, 2)

    # NEW: Test for invalid domain
    def test_get_hiring_trends_invalid_domain(self):
        """Tests that an invalid domain is caught."""
        result = get_hiring_trends("invalid domain")
        self.assertEqual(result.total_postings, 0)
        self.assertIn("Invalid domain", result.error)

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

    # NEW: Test for API error (covers lines 87-91)
    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch(
        "chimera_intel.core.corporate_intel.sync_client.get",
        side_effect=RequestError("API down"),
    )
    def test_get_employee_sentiment_api_error(self, mock_get, mock_api_keys):
        """Tests the employee sentiment function when the API call fails."""
        mock_api_keys.aura_api_key = "fake_aura_key"
        result = get_employee_sentiment("Example Corp")
        self.assertIsInstance(result, EmployeeSentimentResult)
        self.assertIsNone(result.overall_rating)
        self.assertIn("An error occurred with the Aura API", result.error)

    # --- Trade Data Tests ---

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_trade_data_success(self, mock_get, mock_api_keys):
        """Tests the trade data retrieval with a successful API call."""
        mock_api_keys.import_genius_api_key = "fake_ig_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None

        # MODIFIED: Added shipment data to cover list comprehension (lines 102-104)
        mock_response.json.return_value = {
            "total_results": 1,
            "shipments": [
                {
                    "arrival_date": "2023-01-01",
                    "shipper": {"name": "Test Shipper"},
                    "consignee": {"name": "Test Consignee"},
                    "description": "Test Product",
                    "weight_kg": 1000,
                }
            ],
        }
        mock_get.return_value = mock_response

        result = get_trade_data("Example Corp")

        self.assertIsInstance(result, TradeDataResult)
        self.assertEqual(result.total_shipments, 1)
        self.assertEqual(len(result.shipments), 1)
        self.assertIsInstance(result.shipments[0], Shipment)
        self.assertEqual(result.shipments[0].shipper, "Test Shipper")
        self.assertIsNone(result.error)

    # NEW: Test for missing API key
    def test_get_trade_data_no_api_key(self):
        """Tests trade data retrieval when the API key is missing."""
        with patch(
            "chimera_intel.core.corporate_intel.API_KEYS.import_genius_api_key", None
        ):
            result = get_trade_data("Example Corp")
            self.assertIsNotNone(result.error)
            self.assertIn("ImportGenius API key not found", result.error)

    # NEW: Test for API error
    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch(
        "chimera_intel.core.corporate_intel.sync_client.get",
        side_effect=RequestError("API down"),
    )
    def test_get_trade_data_api_error(self, mock_get, mock_api_keys):
        """Tests the trade data function when the API call fails."""
        mock_api_keys.import_genius_api_key = "fake_ig_key"
        result = get_trade_data("Example Corp")
        self.assertEqual(result.total_shipments, 0)
        self.assertIn("An error occurred with the ImportGenius API", result.error)

    # --- Trademark Tests ---

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_trademarks_success(self, mock_get, mock_api_keys):
        """Tests the trademark search with a successful API call."""
        mock_api_keys.uspto_api_key = "fake_uspto_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        # MODIFIED: Added data to cover list comprehension
        mock_response.json.return_value = [
            {
                "serial_number": "123",
                "status_label": "LIVE",
                "description": "Test Mark",
                "owner": {"name": "Example Corp"},
            }
        ]
        mock_get.return_value = mock_response

        result = get_trademarks("Example Corp")
        self.assertIsInstance(result, TrademarkResult)
        self.assertEqual(result.total_found, 1)
        self.assertIsInstance(result.trademarks[0], Trademark)
        self.assertEqual(result.trademarks[0].serial_number, "123")
        self.assertIsNone(result.error)

    # NEW: Test for missing API key (covers line 125)
    def test_get_trademarks_no_api_key(self):
        """Tests trademark search when the API key is missing."""
        with patch("chimera_intel.core.corporate_intel.API_KEYS.uspto_api_key", None):
            result = get_trademarks("Example Corp")
            self.assertEqual(result.total_found, 0)
            self.assertIn("USPTO Trademark API key not found", result.error)

    # NEW: Test for API error (covers lines 136-138)
    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch(
        "chimera_intel.core.corporate_intel.sync_client.get",
        side_effect=RequestError("API down"),
    )
    def test_get_trademarks_api_error(self, mock_get, mock_api_keys):
        """Tests the trademark search function when the API call fails."""
        mock_api_keys.uspto_api_key = "fake_uspto_key"
        result = get_trademarks("Example Corp")
        self.assertEqual(result.total_found, 0)
        self.assertIn("An error occurred with the USPTO Trademark API", result.error)

    # --- Lobbying Data Tests ---

    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch("chimera_intel.core.corporate_intel.sync_client.get")
    def test_get_lobbying_data_success(self, mock_get, mock_api_keys):
        """Tests the lobbying data analysis with a successful API call."""
        mock_api_keys.lobbying_data_api_key = "fake_lobby_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [
                {
                    "lobbying_represents": [
                        {
                            "amount": "50000.00",  # Test string-to-float conversion
                            "year": "2023",
                            "specific_issue": "Test Issue",
                        }
                    ]
                }
            ]
        }
        mock_get.return_value = mock_response

        result = get_lobbying_data("Example Corp")

        self.assertIsInstance(result, LobbyingResult)
        self.assertEqual(result.total_spent, 50000)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].year, 2023)
        self.assertIsNone(result.error)

    # NEW: Test for missing API key (covers line 152)
    def test_get_lobbying_data_no_api_key(self):
        """Tests lobbying data retrieval when the API key is missing."""
        with patch(
            "chimera_intel.core.corporate_intel.API_KEYS.lobbying_data_api_key", None
        ):
            result = get_lobbying_data("Example Corp")
            self.assertEqual(result.total_spent, 0)
            self.assertIn("Lobbying data API key not found", result.error)

    # NEW: Test for API error (covers lines 179-181)
    @patch("chimera_intel.core.corporate_intel.API_KEYS")
    @patch(
        "chimera_intel.core.corporate_intel.sync_client.get",
        side_effect=RequestError("API down"),
    )
    def test_get_lobbying_data_api_error(self, mock_get, mock_api_keys):
        """Tests the lobbying data function when the API call fails."""
        mock_api_keys.lobbying_data_api_key = "fake_lobby_key"
        result = get_lobbying_data("Example Corp")
        self.assertEqual(result.total_spent, 0)
        self.assertIn("An error occurred with the LobbyingData.com API", result.error)

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
        # NEW: Test summary logic
        long_text = "Risk factors summary" + ("." * 700)
        mock_extractor_instance.get_section.return_value = long_text

        with patch(
            "chimera_intel.core.corporate_intel.API_KEYS.sec_api_io_key", "fake_key"
        ):
            result = get_sec_filings_analysis("AAPL")
        self.assertIsInstance(result, SECFilingAnalysis)
        self.assertIn("Risk factors", result.risk_factors_summary)
        self.assertTrue(result.risk_factors_summary.endswith("..."))
        self.assertIsNone(result.error)

    # NEW: Test for missing API key (covers line 195)
    def test_get_sec_filings_no_api_key(self):
        """Tests SEC filing analysis when the API key is missing."""
        with patch("chimera_intel.core.corporate_intel.API_KEYS.sec_api_io_key", None):
            result = get_sec_filings_analysis("AAPL")
            self.assertIsNone(result)

    # NEW: Test for no filings found (covers line 207)
    @patch("chimera_intel.core.corporate_intel.QueryApi")
    def test_get_sec_filings_analysis_no_filings(self, mock_query_api):
        """Tests SEC filing analysis when no 10-K filings are found."""
        mock_query_instance = mock_query_api.return_value
        mock_query_instance.get_filings.return_value = {"filings": []}

        with patch(
            "chimera_intel.core.corporate_intel.API_KEYS.sec_api_io_key", "fake_key"
        ):
            result = get_sec_filings_analysis("AAPL")
            self.assertIsNone(result)

    # NEW: Test for API error (covers lines 222-224)
    @patch(
        "chimera_intel.core.corporate_intel.QueryApi",
        side_effect=Exception("API error"),
    )
    def test_get_sec_filings_analysis_api_error(self, mock_query_api):
        """Tests SEC filing analysis when the QueryApi fails."""
        with patch(
            "chimera_intel.core.corporate_intel.API_KEYS.sec_api_io_key", "fake_key"
        ):
            result = get_sec_filings_analysis("AAPL")
            self.assertIsInstance(result, SECFilingAnalysis)
            self.assertIn("API error", result.error)

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
        mock_hiring.return_value = HiringTrendsResult(total_postings=5, job_postings=[])
        mock_sentiment.return_value = EmployeeSentimentResult(overall_rating=4.0)

        result = runner.invoke(corporate_intel_app, ["hr-intel"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using target 'ProjectCorp' from active project", result.stdout)
        mock_hiring.assert_called_with("project.com")
        mock_sentiment.assert_called_with("ProjectCorp")

    # NEW: Test 'hr-intel' with domain argument (covers 238, 284-285)
    @patch("chimera_intel.core.corporate_intel.get_active_project")
    @patch("chimera_intel.core.corporate_intel.get_hiring_trends")
    @patch("chimera_intel.core.corporate_intel.get_employee_sentiment")
    def test_cli_hr_intel_with_domain_arg(
        self, mock_sentiment, mock_hiring, mock_get_project
    ):
        """Tests 'hr-intel' when a domain is passed as an argument."""
        mock_get_project.return_value = None  # No active project
        mock_hiring.return_value = HiringTrendsResult(total_postings=1, job_postings=[])
        mock_sentiment.return_value = EmployeeSentimentResult(overall_rating=4.0)

        result = runner.invoke(corporate_intel_app, ["hr-intel", "google.com"])

        self.assertEqual(result.exit_code, 0)
        mock_hiring.assert_called_with("google.com")
        mock_sentiment.assert_called_with("google")  # Best effort name
        self.assertNotIn("Using active project", result.stdout)

    # NEW: Test 'hr-intel' with company name argument (covers 238, 317-323)
    @patch("chimera_intel.core.corporate_intel.get_active_project")
    @patch("chimera_intel.core.corporate_intel.get_hiring_trends")
    @patch("chimera_intel.core.corporate_intel.get_employee_sentiment")
    def test_cli_hr_intel_with_company_arg(
        self, mock_sentiment, mock_hiring, mock_get_project
    ):
        """Tests 'hr-intel' when a company name (not domain) is passed."""
        mock_get_project.return_value = None  # No active project
        mock_hiring.return_value = HiringTrendsResult(
            total_postings=0, error="Domain needed"
        )
        mock_sentiment.return_value = EmployeeSentimentResult(overall_rating=4.0)

        result = runner.invoke(corporate_intel_app, ["hr-intel", "Google Inc"])

        self.assertEqual(result.exit_code, 0)
        mock_hiring.assert_not_called()  # No domain
        mock_sentiment.assert_called_with("Google Inc")
        self.assertIn('"error": "Domain needed', result.stdout)

    # NEW: Test 'hr-intel' with no target (covers 264-266)
    @patch("chimera_intel.core.corporate_intel.get_active_project", return_value=None)
    def test_cli_hr_intel_no_target_no_project(self, mock_get_project):
        """Tests 'hr-intel' when no target is given and no project is set."""
        result = runner.invoke(corporate_intel_app, ["hr-intel"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No target provided and no active project set", result.stdout)

    @patch("chimera_intel.core.corporate_intel.get_trade_data")
    def test_cli_supplychain_with_argument(self, mock_get_trade):
        """Tests the 'corporate supplychain' command with a direct argument."""
        mock_get_trade.return_value = TradeDataResult(total_shipments=10, shipments=[])

        result = runner.invoke(corporate_intel_app, ["supplychain", "Test Company"])

        self.assertEqual(result.exit_code, 0)
        mock_get_trade.assert_called_with("Test Company")
        self.assertIn('"total_shipments": 10', result.stdout)

    # NEW: Test 'supplychain' with no target (covers 356-365)
    @patch("chimera_intel.core.corporate_intel.get_active_project", return_value=None)
    def test_cli_supplychain_no_target_no_project(self, mock_get_project):
        """Tests 'supplychain' when no target is given and no project is set."""
        result = runner.invoke(corporate_intel_app, ["supplychain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No company name provided and no active project", result.stdout)

    # NEW: Test 'ip-deep' with argument (covers 441-442)
    @patch("chimera_intel.core.corporate_intel.get_trademarks")
    def test_cli_ip_intel_with_argument(self, mock_get_trademarks):
        """Tests the 'corporate ip-deep' command with a direct argument."""
        mock_get_trademarks.return_value = TrademarkResult(total_found=2, trademarks=[])

        result = runner.invoke(corporate_intel_app, ["ip-deep", "Test Company"])

        self.assertEqual(result.exit_code, 0)
        mock_get_trademarks.assert_called_with("Test Company")
        self.assertIn('"total_found": 2', result.stdout)

    @patch("chimera_intel.core.corporate_intel.get_active_project")
    def test_cli_command_no_target_or_project(self, mock_get_project):
        """Tests 'ip-deep' fails when no target is given and no project is active."""
        mock_get_project.return_value = None

        result = runner.invoke(corporate_intel_app, ["ip-deep"])
        self.assertEqual(result.exit_code, 1)
        cleaned_output = " ".join(result.stdout.strip().split())
        self.assertIn(
            "No company name provided and no active project with a company name is set.",
            cleaned_output,
        )

    # NEW: Test 'regulatory' with argument
    @patch("chimera_intel.core.corporate_intel.get_lobbying_data")
    def test_cli_regulatory_with_argument(self, mock_get_lobbying):
        """Tests the 'corporate regulatory' command with a direct argument."""
        mock_get_lobbying.return_value = LobbyingResult(total_spent=500, records=[])

        result = runner.invoke(corporate_intel_app, ["regulatory", "Lobby Corp"])

        self.assertEqual(result.exit_code, 0)
        mock_get_lobbying.assert_called_with("Lobby Corp")
        self.assertIn('"total_spent": 500', result.stdout)

    # NEW: Test 'regulatory' with no target
    @patch("chimera_intel.core.corporate_intel.get_active_project", return_value=None)
    def test_cli_regulatory_no_target_no_project(self, mock_get_project):
        """Tests 'regulatory' when no target is given and no project is set."""
        result = runner.invoke(corporate_intel_app, ["regulatory"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No company name provided and no active project", result.stdout)

    # NEW: Test 'sec-filings' with argument (covers 469-488)
    @patch("chimera_intel.core.corporate_intel.get_sec_filings_analysis")
    def test_cli_sec_filings_with_argument(self, mock_get_filings):
        """Tests the 'corporate sec-filings' command with a direct argument."""
        mock_get_filings.return_value = SECFilingAnalysis(
            filing_url="http://test.com", risk_factors_summary="Risks!"
        )
        result = runner.invoke(corporate_intel_app, ["sec-filings", "TICKER"])
        self.assertEqual(result.exit_code, 0)
        mock_get_filings.assert_called_with("TICKER")
        self.assertIn('"risk_factors_summary": "Risks!"', result.stdout)

    # NEW: Test 'sec-filings' with no target
    @patch("chimera_intel.core.corporate_intel.get_active_project", return_value=None)
    def test_cli_sec_filings_no_target_no_project(self, mock_get_project):
        """Tests 'sec-filings' when no target is given and no project is set."""
        result = runner.invoke(corporate_intel_app, ["sec-filings"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No ticker provided and no active project", result.stdout)

    # NEW: Test 'sec-filings' when no data is found (covers 522)
    @patch(
        "chimera_intel.core.corporate_intel.get_sec_filings_analysis", return_value=None
    )
    def test_cli_sec_filings_no_data_found(self, mock_get_filings):
        """Tests 'sec-filings' when get_sec_filings_analysis returns None."""
        result = runner.invoke(corporate_intel_app, ["sec-filings", "TICKER"])
        self.assertEqual(result.exit_code, 0)
        mock_get_filings.assert_called_with("TICKER")
        # Should just exit cleanly with no output
        self.assertNotIn('"risk_factors_summary"', result.stdout)


if __name__ == "__main__":
    unittest.main()
