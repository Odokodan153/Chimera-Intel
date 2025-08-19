import unittest
from unittest.mock import patch, MagicMock
from httpx import Response
from chimera_intel.core.personnel_osint import find_employee_emails
from chimera_intel.core.schemas import PersonnelOSINTResult


class TestPersonnelOsint(unittest.TestCase):
    """Test cases for the personnel_osint module."""

    @patch("chimera_intel.core.personnel_osint.API_KEYS")
    @patch("chimera_intel.core.personnel_osint.sync_client.get")
    def test_find_employee_emails_success(self, mock_get, mock_api_keys):
        """Tests a successful employee email search."""
        # Setup the mock API key

        mock_api_keys.hunter_api_key = "fake_hunter_key"

        # Setup the mock API response

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "organization": "Example Corp",
                "emails": [
                    {
                        "value": "j.doe@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "position": "CEO",
                        "phone_number": "123456",
                    }
                ],
            }
        }
        mock_get.return_value = mock_response

        result = find_employee_emails("example.com")

        self.assertIsInstance(result, PersonnelOSINTResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_emails_found, 1)
        self.assertEqual(result.organization_name, "Example Corp")
        self.assertEqual(result.employee_profiles[0].first_name, "John")

    @patch("chimera_intel.core.personnel_osint.API_KEYS")
    def test_find_employee_emails_no_api_key(self, mock_api_keys):
        """Tests the function when the Hunter.io API key is missing."""
        mock_api_keys.hunter_api_key = None

        result = find_employee_emails("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("API key not found", result.error)

    @patch("chimera_intel.core.personnel_osint.API_KEYS")
    @patch("chimera_intel.core.personnel_osint.sync_client.get")
    def test_find_employee_emails_api_error(self, mock_get, mock_api_keys):
        """Tests the function when the Hunter.io API returns an error."""
        mock_api_keys.hunter_api_key = "fake_hunter_key"
        mock_get.side_effect = Exception("Network Error")

        result = find_employee_emails("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("Network Error", result.error)


if __name__ == "__main__":
    unittest.main()
