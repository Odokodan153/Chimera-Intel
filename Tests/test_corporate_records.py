import unittest
from unittest.mock import patch, MagicMock
from httpx import Response

# --- FIXED: All necessary imports are now included ---

from chimera_intel.core.corporate_records import (
    get_company_records,
    screen_sanctions_list,
)
from chimera_intel.core.schemas import CorporateRegistryResult, SanctionsScreeningResult


class TestCorporateRecords(unittest.TestCase):
    """Test cases for the corporate_records module."""

    @patch("chimera_intel.core.corporate_records.API_KEYS")
    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_get_company_records_success(self, mock_get, mock_api_keys):
        """Tests a successful company records search."""
        # Setup the mock API key

        mock_api_keys.open_corporates_api_key = "fake_oc_key"

        # Setup the mock API response

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
                            "registered_address_in_full": "1600 Amphitheatre Parkway, Mountain View, USA",
                            "officers": [
                                {
                                    "officer": {
                                        "name": "SUNDAR PICHAI",
                                        "position": "Chief Executive Officer",
                                    }
                                }
                            ],
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
        self.assertEqual(result.records[0].name, "GOOGLE LLC")
        self.assertEqual(len(result.records[0].officers), 1)
        self.assertEqual(result.records[0].officers[0].name, "SUNDAR PICHAI")

    @patch("chimera_intel.core.corporate_records.API_KEYS")
    def test_get_company_records_no_api_key(self, mock_api_keys):
        """Tests the function when the OpenCorporates API key is missing."""
        mock_api_keys.open_corporates_api_key = None

        result = get_company_records("GOOGLE LLC")
        self.assertIsNotNone(result.error)
        self.assertIn("API key not found", result.error)

    @patch("chimera_intel.core.corporate_records.API_KEYS")
    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_get_company_records_api_error(self, mock_get, mock_api_keys):
        """Tests the function when the OpenCorporates API returns an error."""
        mock_api_keys.open_corporates_api_key = "fake_oc_key"
        mock_get.side_effect = Exception("API connection failed")

        result = get_company_records("GOOGLE LLC")
        self.assertIsNotNone(result.error)
        self.assertIn("API error occurred", result.error)

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_screen_sanctions_list_success_with_hits(self, mock_get):
        """Tests a successful sanctions screening with positive matches."""
        # A simplified HTML response mimicking the OFAC results page

        mock_html = """
        <html><body>
        <table class="table-bordered">
          <tbody>
            <tr>
              <td>IVANOV, Ivan</td>
              <td>Moscow, Russia</td>
              <td>Individual</td>
              <td>RUSSIA-EO123, CYBER2</td>
              <td>100</td>
            </tr>
          </tbody>
        </table>
        </body></html>
        """
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = mock_html
        mock_get.return_value = mock_response

        result = screen_sanctions_list("Ivanov")

        self.assertIsInstance(result, SanctionsScreeningResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.hits_found, 1)
        self.assertEqual(result.entities[0].name, "IVANOV, Ivan")
        self.assertIn("CYBER2", result.entities[0].programs)

    @patch("chimera_intel.core.corporate_records.sync_client.get")
    def test_screen_sanctions_list_no_hits(self, mock_get):
        """Tests a sanctions screening that returns no matches."""
        # OFAC returns a page without the results table when there are no hits

        mock_html = "<html><body>No results found.</body></html>"
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = mock_html
        mock_get.return_value = mock_response

        result = screen_sanctions_list("John Doe")
        self.assertEqual(result.hits_found, 0)
        self.assertEqual(len(result.entities), 0)


if __name__ == "__main__":
    unittest.main()
