import unittest
import json
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

    def test_search_court_dockets_no_api_key(self):
        """Tests the function's behavior when the API key is missing."""
        with patch("chimera_intel.core.legint.API_KEYS.courtlistener_api_key", None):
            result = search_court_dockets("TestCorp")
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

    @patch("chimera_intel.core.legint.search_court_dockets")
    def test_cli_docket_search_with_argument(self, mock_search):
        """Tests the 'legint docket-search' command with a direct argument."""
        # Arrange

        mock_search.return_value = DocketSearchResult(
            query="TestCorp", total_found=1, records=[]
        )

        # Act

        result = runner.invoke(
            legint_app, ["docket-search", "--company-name", "TestCorp"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.exception)
        mock_search.assert_called_with("TestCorp")
        output = json.loads(result.stdout)
        self.assertEqual(output["query"], "TestCorp")
        self.assertEqual(output["total_found"], 1)

    @patch("chimera_intel.core.legint.resolve_target")
    @patch("chimera_intel.core.legint.search_court_dockets")
    def test_cli_docket_search_with_project(self, mock_search, mock_resolve_target):
        """Tests the CLI command using an active project's company name."""
        # Arrange

        mock_resolve_target.return_value = "ProjectCorp"
        mock_search.return_value = DocketSearchResult(
            query="ProjectCorp", total_found=5
        )

        # Act

        result = runner.invoke(legint_app, ["docket-search"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.exception)
        mock_resolve_target.assert_called_with(None, required_assets=["company_name"])
        mock_search.assert_called_with("ProjectCorp")
        self.assertIn('"total_found": 5', result.stdout)


if __name__ == "__main__":
    unittest.main()
