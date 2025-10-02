import unittest
from unittest.mock import patch, MagicMock
from httpx import Response
from typer.testing import CliRunner
import typer

# Corrected: Import the specific Typer app for this module

from chimera_intel.core.legint import legint_app, search_court_dockets
from chimera_intel.core.schemas import DocketSearchResult

runner = CliRunner()


class TestLegint(unittest.TestCase):
    """
    Unit tests for the Legal Intelligence (LEGINT) module using mocks.
    """

    @patch("chimera_intel.core.legint.API_KEYS")
    @patch("chimera_intel.core.legint.sync_client.get")
    def test_search_court_dockets_success(self, mock_get, mock_api_keys):
        """Tests a successful court docket search by mocking the API call."""
        # Arrange

        mock_api_keys.courtlistener_api_key = "fake_court_key"
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "count": 1,
            "results": [
                {
                    "caseName": "Apple Inc. v. Samsung Electronics Co.",
                    "dateFiled": "2011-04-15",
                    "court": "nvd",
                    "absolute_url": "/docket/4232353/apple-inc-v-samsung-electronics-co/",
                    "docketNumber": "5:11-cv-01846",
                }
            ],
        }
        mock_get.return_value = mock_response

        # Act

        result = search_court_dockets("Apple Inc.")

        # Assert

        self.assertIsInstance(result, DocketSearchResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_found, 1)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].court, "nvd")
        # Verify that the HTTP client was called correctly

        mock_get.assert_called_once()

    @patch("chimera_intel.core.legint.API_KEYS")
    def test_search_court_dockets_no_api_key(self, mock_api_keys):
        """Tests the function's behavior when the API key is missing."""
        # Arrange

        mock_api_keys.courtlistener_api_key = None

        # Act

        result = search_court_dockets("Example Corp")

        # Assert

        self.assertIsInstance(result, DocketSearchResult)
        self.assertIsNotNone(result.error)
        self.assertIn("API key not found", result.error)

    @patch("chimera_intel.core.legint.API_KEYS")
    @patch("chimera_intel.core.legint.sync_client.get")
    def test_search_court_dockets_api_error(self, mock_get, mock_api_keys):
        """Tests the function's error handling when the API call fails."""
        # Arrange

        mock_api_keys.courtlistener_api_key = "fake_court_key"
        mock_get.side_effect = Exception("API connection timed out")

        # Act

        result = search_court_dockets("Example Corp")

        # Assert

        self.assertIsInstance(result, DocketSearchResult)
        self.assertIsNotNone(result.error)
        self.assertIn("API error occurred", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.legint.resolve_target")
    @patch("chimera_intel.core.legint.search_court_dockets")
    def test_cli_docket_search_with_project(
        self, mock_search_dockets, mock_resolve_target
    ):
        """Tests the 'legint docket-search' command using the centralized resolver."""
        # Arrange

        mock_resolve_target.return_value = "Project Corp"
        mock_search_dockets.return_value.model_dump.return_value = {}

        # Act
        # FIX: When a Typer app has one command, invoke with an empty list
        # to test the no-argument case (relying on project context).

        result = runner.invoke(legint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_with(None, required_assets=["company_name"])
        mock_search_dockets.assert_called_with("Project Corp")

    @patch("chimera_intel.core.legint.resolve_target")
    def test_cli_docket_search_resolver_fails(self, mock_resolve_target):
        """Tests CLI failure when the resolver raises an exit exception."""
        # Arrange

        mock_resolve_target.side_effect = typer.Exit(code=1)

        # Act
        # Corrected: Use legint_app instead of the main app

        result = runner.invoke(legint_app, ["docket-search"])

        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
