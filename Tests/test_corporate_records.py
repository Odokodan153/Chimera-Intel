import unittest
import os
import json
from unittest.mock import patch, MagicMock, mock_open
from httpx import Response
from typer.testing import CliRunner
import typer

# Import the specific Typer app for this module

from chimera_intel.core.corporate_records import corporate_records_app
from chimera_intel.core.corporate_records import (
    get_company_records,
    screen_sanctions_list,
    screen_pep_list,
    load_pep_list,
    PEP_FILE_PATH,
    PEP_LIST_CACHE,
)
from chimera_intel.core.schemas import (
    CorporateRegistryResult,
    SanctionsScreeningResult,
    PEPScreeningResult
)

runner = CliRunner()


class TestCorporateRecords(unittest.TestCase):
    """Extended and corrected test cases for the corporate_records module."""

    def setUp(self):
        """Clear the in-memory cache and remove the test file before each test."""
        PEP_LIST_CACHE.clear()
        if os.path.exists(PEP_FILE_PATH):
            os.remove(PEP_FILE_PATH)

    def tearDown(self):
        """Clean up the test file after tests to ensure test isolation."""
        if os.path.exists(PEP_FILE_PATH):
            os.remove(PEP_FILE_PATH)

    @patch("chimera_intel.core.corporate_records.API_KEYS")
    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_get_company_records_success(self, mock_get, mock_api_keys):
        """Tests a successful company records search with a corrected mock."""
        mock_api_keys.open_corporates_api_key = "fake_oc_key"
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {
                "total_count": 1,
                "companies": [
                    {"company": {"name": "GOOGLE LLC", "company_number": "20231234567"}}
                ],
            }
        }
        mock_get.return_value = mock_response

        result = get_company_records("GOOGLE LLC")
        self.assertIsInstance(result, CorporateRegistryResult)
        self.assertEqual(result.total_found, 1)
        self.assertEqual(result.records[0].name, "GOOGLE LLC")

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_screen_sanctions_list_success(self, mock_get):
        """Tests a successful OFAC sanctions list screen."""
        mock_html_with_results = """
        <html><table class="table-bordered"><tbody>
            <tr><td>JOHN DOE</td><td>CUBA</td><td>Individual</td><td>CUBA</td><td>100</td></tr>
        </tbody></table></html>
        """
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = mock_html_with_results
        mock_get.return_value = mock_response

        result = screen_sanctions_list("JOHN DOE")
        self.assertIsInstance(result, SanctionsScreeningResult)
        self.assertEqual(result.hits_found, 1)
        self.assertEqual(result.entities[0].name, "JOHN DOE")

    @patch(
        "chimera_intel.core.corporate_records.load_pep_list", return_value={"JOHN DOE"}
    )
    def test_screen_pep_list_found(self, mock_load_pep):
        """Tests a successful PEP screen where the name is found."""
        result = screen_pep_list("JOHN DOE")
        self.assertIsInstance(result, PEPScreeningResult)
        self.assertTrue(result.is_pep)

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    @patch("os.path.exists", return_value=False)
    @patch("builtins.open", new_callable=mock_open)
    def test_load_pep_list_downloads_if_not_exists(
        self, mock_file_open, mock_path_exists, mock_get
    ):
        """Tests that the PEP list is downloaded, written, and then read correctly."""
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.text = "JOHN DOE\nJANE SMITH"
        mock_get.return_value = mock_response

        pep_list = load_pep_list()

        mock_get.assert_called_once()
        mock_file_open.assert_called_with(PEP_FILE_PATH, "w", encoding="utf-8")
        self.assertIn("JOHN DOE", pep_list)
        self.assertIn("JANE SMITH", pep_list)

    def test_load_pep_list_uses_cache(self):
        """Tests that the PEP list loader uses the in-memory cache correctly."""
        PEP_LIST_CACHE.add("CACHED NAME")
        with patch("builtins.open") as mock_open_call:
            pep_list = load_pep_list()
            mock_open_call.assert_not_called()
            self.assertIn("CACHED NAME", pep_list)

    # --- CLI Tests ---

    @patch("chimera_intel.core.corporate_records.resolve_target")
    @patch("chimera_intel.core.corporate_records.get_company_records")
    def test_cli_registry_with_project(self, mock_get_records, mock_resolve_target):
        """Tests the 'registry' command using the centralized resolver."""
        mock_resolve_target.return_value = "Project Corp"
        mock_get_records.return_value = CorporateRegistryResult(
            query="Project Corp", total_found=0
        )

        result = runner.invoke(corporate_records_app, ["registry"])

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_with(None, required_assets=["company_name"])
        mock_get_records.assert_called_with("Project Corp")

    @patch("chimera_intel.core.corporate_records.resolve_target")
    def test_cli_sanctions_resolver_fails(self, mock_resolve_target):
        """Tests the 'sanctions' command when the resolver fails."""
        mock_resolve_target.side_effect = typer.Exit(code=1)
        result = runner.invoke(corporate_records_app, ["sanctions"])
        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.corporate_records.screen_pep_list")
    def test_cli_pep_with_argument(self, mock_screen_pep):
        """: Tests the 'pep' command with a direct argument."""
        mock_screen_pep.return_value = PEPScreeningResult(query="John Doe", is_pep=True)

        result = runner.invoke(corporate_records_app, ["pep", "John Doe"])

        self.assertEqual(result.exit_code, 0)
        mock_screen_pep.assert_called_with("John Doe")
        output = json.loads(result.stdout)
        self.assertTrue(output["is_pep"])


if __name__ == "__main__":
    unittest.main()
