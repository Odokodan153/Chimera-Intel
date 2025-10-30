import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from httpx import Response, RequestError

from chimera_intel.core.legint import search_court_dockets, legint_app
from chimera_intel.core.schemas import DocketSearchResult

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

        mock_resolve.return_value = "TestCorp"
        report = DocketSearchResult(query="TestCorp", total_found=1, records=[])
        mock_search.return_value = report
        expected_dict = report.model_dump(exclude_none=True, by_alias=True)

        # Act
        # Corrected: Pass options directly, not the command name

        result = runner.invoke(legint_app, ["--company-name", "TestCorp"])

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIsNone(result.exception)  # Added this check
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

        mock_resolve_target.return_value = "ProjectCorp"
        mock_search.return_value = DocketSearchResult(
            query="ProjectCorp", total_found=5, records=[]
        )

        # Act
        # Corrected: Pass no company_name to use active project

        result = runner.invoke(legint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIsNone(result.exception)  # Added this check
        mock_resolve_target.assert_called_with(None, required_assets=["company_name"])
        mock_search.assert_called_with("ProjectCorp")


if __name__ == "__main__":
    unittest.main()
