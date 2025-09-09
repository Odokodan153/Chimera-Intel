import unittest
import os
from unittest.mock import patch, MagicMock, mock_open
from httpx import Response
from typer.testing import CliRunner

# Import the main Typer app to test CLI commands

from chimera_intel.cli import app

from chimera_intel.core.corporate_records import (
    get_company_records,
    load_pep_list,
    PEP_FILE_PATH,
    PEP_LIST_CACHE,
)
from chimera_intel.core.schemas import (
    CorporateRegistryResult,
)

# Initialize the test runner

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
        """Tests a successful company records search."""
        mock_api_keys.open_corporates_api_key = "fake_oc_key"
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        # FIX: The mock data structure now exactly matches what the function expects.

        mock_response.json.return_value = {
            "results": {
                "total_count": 1,
                "companies": [
                    {
                        "company": {
                            "name": "GOOGLE LLC",
                            "company_number": "20231234567",
                            "jurisdiction_code": "us_ca",
                            "inactive": False,
                            "registered_address_in_full": "1600 Amphitheatre Parkway",
                            "officers": [],
                        }
                    }
                ],
            }
        }
        mock_get.return_value = mock_response

        result = get_company_records("GOOGLE LLC")

        self.assertIsInstance(result, CorporateRegistryResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_found, 1)
        self.assertEqual(len(result.records), 1)

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    @patch("os.path.exists", return_value=False)
    def test_load_pep_list_downloads_if_not_exists(self, mock_exists, mock_get):
        """Tests that the PEP list is downloaded, written, and then read correctly."""
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.text = "JOHN DOE"
        mock_get.return_value = mock_response

        # FIX: Correctly mock the file read operation after the write.

        m = mock_open()
        with patch("builtins.open", m):
            # When the file is read after being "written", simulate its content.

            m.return_value.__iter__.return_value = ["JOHN DOE"]

            pep_list = load_pep_list()

            # Assert the file was opened for writing.

            m.assert_any_call(PEP_FILE_PATH, "w", encoding="utf-8")
            self.assertIn("JOHN DOE", pep_list)

    def test_load_pep_list_uses_cache(self):
        """Tests that the PEP list loader uses the in-memory cache correctly."""
        # FIX: Populate the cache before calling the function.

        PEP_LIST_CACHE.add("CACHED NAME")
        pep_list = load_pep_list()

        # The assertion now correctly checks the pre-populated cache.

        self.assertIn("CACHED NAME", pep_list)

    # --- NEW: CLI Command Tests ---

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
