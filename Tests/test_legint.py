import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from httpx import Response, RequestError
import re

from chimera_intel.core.legint import (
    search_court_dockets,
    search_arbitration_records,
    check_export_controls,
    search_lobbying_data,
    legint_app,
    screen_for_sanctions, # Added imports for patched functions
    get_ubo_data
)
from chimera_intel.core.schemas import (
    DocketSearchResult,
    ArbitrationSearchResult,
    ExportControlResult,
    LobbyingSearchResult,
    SanctionsScreeningResult, # Added imports for schemas
    UboResult
)

runner = CliRunner()


class TestLegint(unittest.TestCase):
    """Test cases for the Legal Intelligence (LEGINT) module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.legint.sync_client.get")
    @patch("chimera_intel.core.legint.API_KEYS")
    def test_search_court_dockets_success(self, mock_api_keys, mock_get):
        """Tests a successful court docket search."""
        # Arrange
        mock_api_keys.courtlistener_api_key = "fake_cl_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "count": 1,
            "results": [
                {
                    "caseName": "Test v. Corp",
                    "dateFiled": "2023-01-01",
                    "court": "Test Court",
                    "absolute_url": "/docket/123/",
                    "docketNumber": "1:23-cv-00123",
                }
            ],
        }
        mock_get.return_value = mock_response

        # Act
        result = search_court_dockets("TestCorp")

        # Assert
        self.assertIsInstance(result, DocketSearchResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_found, 1)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].case_name, "Test v. Corp")

    @patch("chimera_intel.core.legint.API_KEYS")
    def test_search_court_dockets_no_api_key(self, mock_api_keys):
        """Tests the function's behavior when the API key is missing."""
        # Arrange
        mock_api_keys.courtlistener_api_key = None

        # Act
        result = search_court_dockets("TestCorp")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("CourtListener API key not found", result.error)

    @patch("chimera_intel.core.legint.sync_client.get")
    @patch("chimera_intel.core.legint.API_KEYS")
    def test_search_court_dockets_api_error(self, mock_api_keys, mock_get):
        """Tests the function's error handling when the API fails."""
        # Arrange
        mock_api_keys.courtlistener_api_key = "fake_cl_key"
        mock_get.side_effect = RequestError("Service Unavailable")

        # Act
        result = search_court_dockets("TestCorp")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)

    # --- NEW TESTS ---

    @patch("chimera_intel.core.legint.search_google")
    def test_search_arbitration_records_success(self, mock_search_google):
        """Tests a successful arbitration search."""
        # Arrange
        mock_search_google.return_value = [
            {
                "title": "MegaCorp Arbitration Case",
                "url": "http://example.com/case1",
                "snippet": "The arbitration between MegaCorp and Client..."
            },
            {
                "title": "MegaCorp Legal Dispute",
                "url": "http://example.com/case2",
                "snippet": "A major legal dispute settled..."
            }
        ]

        # Act
        result = search_arbitration_records("MegaCorp")

        # Assert
        self.assertIsInstance(result, ArbitrationSearchResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0].case_title, "MegaCorp Arbitration Case")
        self.assertEqual(result.findings[0].case_type, "Arbitration")
        self.assertEqual(result.findings[1].case_type, "Dispute/Litigation")
        mock_search_google.assert_called_with(
            '"MegaCorp" AND (arbitration OR "legal dispute" OR lawsuit OR settlement)',
            num_results=10
        )

    @patch("chimera_intel.core.legint.search_google")
    def test_check_export_controls_success(self, mock_search_google):
        """Tests a successful export controls check."""
        # Arrange
        mock_search_google.return_value = [
            {
                "title": "Consolidated Screening List",
                "url": "http://trade.gov/csl",
                "snippet": "MegaCorp... found on Consolidated Screening List."
            },
            {
                "title": "BIS Entity List",
                "url": "http://bis.doc.gov/list",
                "snippet": "MegaCorp... added to Entity List."
            }
        ]

        # Act
        result = check_export_controls("MegaCorp", country_code="US")

        # Assert
        self.assertIsInstance(result, ExportControlResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0].source_list, "US Consolidated Screening List")
        self.assertEqual(result.findings[1].source_list, "BIS Entity List")

    @patch("chimera_intel.core.legint.search_google")
    def test_search_lobbying_data_success(self, mock_search_google):
        """Tests a successful lobbying data search."""
        # Arrange
        mock_search_google.side_effect = [
            # First call (opensecrets)
            [
                {
                    "title": "MegaCorp Lobbying Profile",
                    "url": "http://opensecrets.org/megacorp",
                    "snippet": "Spent $1,200,000 on lobbying in 2023."
                }
            ],
            # Second call (fec.gov)
            [
                {
                    "title": "MegaCorp Donations",
                    "url": "http://fec.gov/megacorp",
                    "snippet": "Donated $50,000 to candidates."
                }
            ]
        ]

        # Act
        result = search_lobbying_data("MegaCorp")

        # Assert
        self.assertIsInstance(result, LobbyingSearchResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.activities), 2)
        self.assertEqual(result.activities[0].amount, 1200000.0)
        self.assertEqual(result.activities[1].amount, 50000.0)
        
        # Check that both queries were made
        self.assertEqual(mock_search_google.call_count, 2)
        mock_search_google.assert_any_call(
            '"MegaCorp" lobbying expenditures site:opensecrets.org',
            num_results=3
        )
        mock_search_google.assert_any_call(
            '"MegaCorp" political donations site:fec.gov',
            num_results=3
        )

    # --- CLI Tests ---

    @patch("chimera_intel.core.legint.resolve_target")
    @patch("chimera_intel.core.legint.search_court_dockets")
    @patch("chimera_intel.core.legint.save_scan_to_db")
    @patch("chimera_intel.core.legint.save_or_print_results")
    def test_cli_docket_search_with_argument(
        self, mock_save_print, mock_save_db, mock_search, mock_resolve
    ):
        """Tests the 'legint docket-search' command with a direct argument."""
        # Arrange
        # ** CORRECTED ARGUMENT ORDER **
        # The arguments are passed in reverse order of the decorators
        mock_resolve.return_value = "TestCorp"
        report = DocketSearchResult(query="TestCorp", total_found=1, records=[])
        mock_search.return_value = report
        expected_dict = report.model_dump(exclude_none=True, by_alias=True)

        # Act
        result = runner.invoke(legint_app, ["docket-search", "--company-name", "TestCorp"])

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIsNone(result.exception)
        mock_search.assert_called_with("TestCorp")
        mock_save_print.assert_called_with(expected_dict, None)
        mock_save_db.assert_called_with(
            target="TestCorp", module="legint_docket_search", data=expected_dict
        )

    @patch("chimera_intel.core.legint.resolve_target")
    @patch("chimera_intel.core.legint.search_court_dockets")
    @patch("chimera_intel.core.legint.save_scan_to_db")
    @patch("chimera_intel.core.legint.save_or_print_results")
    def test_cli_docket_search_with_project(
        self, mock_save_print, mock_save_db, mock_search, mock_resolve_target
    ):
        """Tests the CLI command using an active project's company name."""
        # Arrange
        # ** CORRECTED ARGUMENT ORDER **
        mock_resolve_target.return_value = "ProjectCorp"
        mock_search.return_value = DocketSearchResult(
            query="ProjectCorp", total_found=5, records=[]
        )

        # Act
        result = runner.invoke(legint_app, ["docket-search"])

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIsNone(result.exception)
        mock_resolve_target.assert_called_with(None, required_assets=["company_name"])
        mock_search.assert_called_with("ProjectCorp")

    # --- NEW CLI TESTS ---

    @patch("chimera_intel.core.legint.resolve_target")
    @patch("chimera_intel.core.legint.search_lobbying_data")
    @patch("chimera_intel.core.legint.save_scan_to_db")
    def test_cli_lobbying_search(self, mock_save_db, mock_search, mock_resolve):
        """Tests the 'legint lobbying-search' command."""
        # Arrange
        # ** CORRECTED ARGUMENT ORDER **
        mock_resolve.return_value = "TestCorp"
        mock_search.return_value = LobbyingSearchResult(query="TestCorp", activities=[])

        # Act
        result = runner.invoke(legint_app, ["lobbying-search", "-n", "TestCorp"])

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIsNone(result.exception)
        mock_resolve.assert_called_with("TestCorp", required_assets=["company_name"])
        mock_search.assert_called_with("TestCorp")
        mock_save_db.assert_called()

    @patch("chimera_intel.core.legint.resolve_target")
    @patch("chimera_intel.core.legint.screen_for_sanctions")
    @patch("chimera_intel.core.legint.check_export_controls")
    @patch("chimera_intel.core.legint.get_ubo_data")
    @patch("chimera_intel.core.legint.save_scan_to_db")
    def test_cli_sanctions_screener_all_flags(
        self, mock_save_db, mock_get_ubo, mock_export_check, mock_sanctions, mock_resolve
    ):
        """Tests the 'sanctions-screener' command with --ubo and --export-controls."""
        # Arrange
        # ** CORRECTED: Added mock_resolve to signature and fixed order **
        mock_resolve.return_value = "TestCorp"
        mock_sanctions.return_value = SanctionsScreeningResult(query="TestCorp", hits_found=0, entities=[])
        mock_export_check.return_value = ExportControlResult(query="TestCorp", findings=[])
        # ** CORRECTED: Use UboResult for get_ubo_data mock **
        mock_get_ubo.return_value = UboResult(company_name="TestCorp", ultimate_beneficial_owners=[])

        # Act
        result = runner.invoke(
            legint_app,
            ["sanctions-screener", "-n", "TestCorp", "--ubo", "--export-controls"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIsNone(result.exception)
        mock_resolve.assert_called_with("TestCorp", required_assets=["company_name"])
        mock_sanctions.assert_called_with("TestCorp")
        mock_export_check.assert_called_with("TestCorp")
        mock_get_ubo.assert_called_with("TestCorp")
        mock_save_db.assert_called()


if __name__ == "__main__":
    unittest.main()