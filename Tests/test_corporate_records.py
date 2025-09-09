import unittest
import os
from unittest.mock import patch, MagicMock, mock_open
from httpx import Response
from typer.testing import CliRunner
from chimera_intel.core.corporate_records import (
    get_company_records,
    load_pep_list,
    PEP_FILE_PATH,
    PEP_LIST_CACHE,
)
from chimera_intel.core.schemas import CorporateRegistryResult

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

    # This test was failing due to an incorrect mock data structure.
    # It has been corrected to match what the application code expects.

    @patch("chimera_intel.core.corporate_records.API_KEYS")
    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_get_company_records_success(self, mock_get, mock_api_keys):
        """Tests a successful company records search."""
        mock_api_keys.open_corporates_api_key = "fake_oc_key"
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {
                "total_count": 1,
                "company": {
                    "name": "GOOGLE LLC",
                    "company_number": "20231234567",
                    "jurisdiction_code": "us_ca",
                    "inactive": False,
                    "registered_address_in_full": "1600 Amphitheatre Parkway",
                    "officers": [],
                },
            }
        }
        mock_get.return_value = mock_response

        result = get_company_records("GOOGLE LLC")
        self.assertIsInstance(result, CorporateRegistryResult)
        self.assertEqual(result.total_found, 1)
        self.assertEqual(len(result.records), 1)

    # This test was failing because the mock for the 'open' function
    # did not correctly simulate reading the file after it was written.
    # This version uses a more robust mock that handles both operations.

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    @patch("os.path.exists", return_value=False)
    def test_load_pep_list_downloads_if_not_exists(self, mock_exists, mock_get):
        """Tests that the PEP list is downloaded, written, and then read correctly."""
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.text = "JOHN DOE\nJANE SMITH"
        mock_get.return_value = mock_response

        # This mock now correctly simulates the content for the read operation.

        m = mock_open(read_data="JOHN DOE\nJANE SMITH")
        with patch("builtins.open", m):
            pep_list = load_pep_list()

            # Assert that the file was opened for writing.

            m.assert_any_call(PEP_FILE_PATH, "w", encoding="utf-8")
            # Assert that the downloaded content was written to the file handle.

            m().write.assert_called_once_with("JOHN DOE\nJANE SMITH")
            # Assert the final result contains the uppercased data.

            self.assertIn("JOHN DOE", pep_list)
            self.assertIn("JANE SMITH", pep_list)

    # This test was failing because of issues with managing the global cache
    # state between tests. This version uses a patch to reliably control
    # the cache's state for this specific test.

    @patch("chimera_intel.core.corporate_records.os.path.exists")
    def test_load_pep_list_uses_cache(self, mock_exists):
        """Tests that the PEP list loader uses the in-memory cache correctly."""
        # Patch the global variable directly for this test's scope.

        with patch(
            "chimera_intel.core.corporate_records.PEP_LIST_CACHE", {"CACHED NAME"}
        ):
            pep_list = load_pep_list()

            # Assert the result is the cached data.

            self.assertIn("CACHED NAME", pep_list)
            # Assert that the function returned early and did not try to access the file system.

            mock_exists.assert_not_called()
