import unittest
import os
from unittest.mock import patch, MagicMock, mock_open
from httpx import Response, RequestError

from chimera_intel.core.corporate_records import (
    get_company_records,
    screen_sanctions_list,
    load_pep_list,
    PEP_FILE_PATH,
    PEP_LIST_CACHE,
)
from chimera_intel.core.schemas import CorporateRegistryResult
from typer.testing import CliRunner
from chimera_intel.cli import app

runner = CliRunner()


class TestCorporateRecords(unittest.TestCase):
    """Extended test cases for the corporate_records module."""

    def setUp(self):
        """Clear the in-memory cache before each test."""
        PEP_LIST_CACHE.clear()

    def tearDown(self):
        """Ensure the test PEP file is removed after tests if it was created."""
        if os.path.exists(PEP_FILE_PATH):
            os.remove(PEP_FILE_PATH)

    @patch("chimera_intel.core.corporate_records.API_KEYS")
    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_get_company_records_success(self, mock_get, mock_api_keys):
        """Tests a successful company records search."""
        mock_api_keys.open_corporates_api_key = "fake_oc_key"
        mock_response = MagicMock(spec=Response, status_code=200)
        mock_response.json.return_value = {
            "results": {
                "total_count": 1,
                "companies": [{"company": {"name": "GOOGLE LLC"}}],
            }
        }
        mock_get.return_value = mock_response
        result = get_company_records("GOOGLE LLC")
        self.assertIsInstance(result, CorporateRegistryResult)
        self.assertEqual(result.total_found, 1)

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_screen_sanctions_list_request_error(self, mock_get):
        """Tests the sanctions screening when an HTTP request fails."""
        mock_get.side_effect = RequestError("Network down")
        result = screen_sanctions_list("Ivanov")
        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred during screening", result.error)

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    @patch("os.path.exists", return_value=False)
    def test_load_pep_list_downloads_if_not_exists(self, mock_exists, mock_get):
        """Tests that the PEP list is downloaded if the local file is missing."""
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.text = "JOHN DOE\nJANE SMITH"
        mock_get.return_value = mock_response

        with patch("builtins.open", mock_open()) as mock_file:
            pep_list = load_pep_list()
            mock_file.assert_called_with(PEP_FILE_PATH, "w", encoding="utf-8")
            self.assertIn("JOHN DOE", pep_list)

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    @patch("os.path.exists", return_value=False)
    def test_load_pep_list_download_fails(self, mock_exists, mock_get):
        """Tests the PEP list loader when the download fails."""
        mock_get.side_effect = RequestError("Download failed")
        pep_list = load_pep_list()
        self.assertEqual(pep_list, set())

    def test_load_pep_list_uses_cache(self):
        """Tests that the PEP list loader uses the in-memory cache on subsequent calls."""
        PEP_LIST_CACHE.add("CACHED NAME")
        # We don't need to mock anything else because if the cache is hit,
        # no file I/O or network calls should be made.

        pep_list = load_pep_list()
        self.assertIn("CACHED NAME", pep_list)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.corporate_records.get_company_records")
    def test_cli_registry_command(self, mock_get_records):
        """Tests the 'compliance registry' CLI command."""
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "query": "Example Corp",
            "total_found": 1,
        }
        mock_get_records.return_value = mock_result

        result = runner.invoke(app, ["compliance", "registry", "Example Corp"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_found": 1', result.stdout)

    @patch("chimera_intel.core.corporate_records.screen_sanctions_list")
    def test_cli_sanctions_command(self, mock_screen_sanctions):
        """Tests the 'compliance sanctions' CLI command."""
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {"query": "John Doe", "hits_found": 0}
        mock_screen_sanctions.return_value = mock_result

        result = runner.invoke(app, ["compliance", "sanctions", "John Doe"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"hits_found": 0', result.stdout)

    @patch("chimera_intel.core.corporate_records.screen_pep_list")
    def test_cli_pep_command(self, mock_screen_pep):
        """Tests the 'compliance pep' CLI command."""
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {"query": "Jane Smith", "is_pep": True}
        mock_screen_pep.return_value = mock_result

        result = runner.invoke(app, ["compliance", "pep", "Jane Smith"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"is_pep": true', result.stdout)


if __name__ == "__main__":
    unittest.main()
