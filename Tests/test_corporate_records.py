import unittest
import os
from unittest.mock import patch, MagicMock, mock_open
from httpx import Response
from typer.testing import CliRunner
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
    PEPScreeningResult,
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
                    {
                        "company": {
                            "name": "GOOGLE LLC",
                            "company_number": "20231234567",
                            "jurisdiction_code": "us_ca",
                            "inactive": False,
                            "officers": [],
                        }
                    }
                ],
            }
        }
        mock_get.return_value = mock_response

        result = get_company_records("GOOGLE LLC")
        self.assertIsInstance(result, CorporateRegistryResult)
        self.assertEqual(result.total_found, 1)

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_screen_sanctions_list_success(self, mock_get):
        """Tests a successful OFAC sanctions list screen."""
        mock_html_with_results = """
        <html>
            <table class="table-bordered">
                <tbody>
                    <tr>
                        <td>JOHN DOE</td>
                        <td>CUBA</td>
                        <td>Individual</td>
                        <td>CUBA</td>
                        <td>100</td>
                    </tr>
                </tbody>
            </table>
        </html>
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
    def test_load_pep_list_downloads_if_not_exists(self, mock_exists, mock_get):
        """Tests that the PEP list is downloaded, written, and then read correctly."""
        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.text = "JOHN DOE\nJANE SMITH"
        mock_get.return_value = mock_response

        # Use mock_open to simulate the file being written and then read.

        m = mock_open()
        with patch("builtins.open", m):
            # When open is called for reading, simulate the content that was "written".

            m.return_value.read.return_value = "JOHN DOE\nJANE SMITH"
            m.return_value.__iter__.return_value = ["JOHN DOE", "JANE SMITH"]

            # The first call to load_pep_list should trigger the download and write.

            pep_list = load_pep_list()

            # Assert that the download happened.

            mock_get.assert_called_once()
            # Assert that the file was opened for writing.

            m.assert_any_call(PEP_FILE_PATH, "w", encoding="utf-8")
            # Assert that the list was loaded correctly.

            self.assertIn("JOHN DOE", pep_list)
            self.assertIn("JANE SMITH", pep_list)

    def test_load_pep_list_uses_cache(self):
        """Tests that the PEP list loader uses the in-memory cache correctly."""
        # Pre-populate the cache.

        PEP_LIST_CACHE.add("CACHED NAME")

        # This call should hit the cache and not touch the file system.

        with patch("builtins.open") as mock_open_call:
            pep_list = load_pep_list()
            # Assert that open() was NOT called because the cache was used.

            mock_open_call.assert_not_called()
            # Assert that the cached item is in the result.

            self.assertIn("CACHED NAME", pep_list)


if __name__ == "__main__":
    unittest.main()
