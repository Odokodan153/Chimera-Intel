import unittest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.personnel_osint import find_employee_emails, personnel_osint_app
from chimera_intel.core.schemas import (
    PersonnelOSINTResult,
    ProjectConfig,
)

runner = CliRunner()


class TestPersonnelOsint(unittest.TestCase):
    """Test cases for the Personnel OSINT module."""

    @patch("chimera_intel.core.personnel_osint.sync_client.get")
    @patch("chimera_intel.core.personnel_osint.API_KEYS")
    def test_find_employee_emails_success(self, mock_api_keys, mock_get):
        """Tests a successful employee email search."""
        # Arrange

        mock_api_keys.hunter_api_key = "fake_hunter_key"
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.status_code = 200
        # CORRECTED: The API returns 'value' for the email, which is mapped to 'email' in the schema

        mock_response.json.return_value = {
            "data": {
                "organization": "Example Corp",
                "emails": [
                    {
                        "value": "j.doe@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "position": "Engineer",
                    }
                ],
            }
        }
        mock_get.return_value = mock_response

        # Act

        result = find_employee_emails("example.com")

        # Assert

        self.assertIsInstance(result, PersonnelOSINTResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_emails_found, 1)
        self.assertEqual(result.employee_profiles[0].email, "j.doe@example.com")
        self.assertEqual(result.employee_profiles[0].first_name, "John")

    def test_find_employee_emails_no_api_key(self):
        """Tests the function's behavior when the Hunter.io API key is missing."""
        with patch("chimera_intel.core.personnel_osint.API_KEYS.hunter_api_key", None):
            result = find_employee_emails("example.com")
            self.assertIsNotNone(result.error)
            self.assertIn("Hunter.io API key not found", result.error)

    @patch("chimera_intel.core.personnel_osint.sync_client.get")
    @patch("chimera_intel.core.personnel_osint.API_KEYS")
    def test_find_employee_emails_invalid_api_key(self, mock_api_keys, mock_get):
        """Tests the function's handling of an invalid API key (401 response)."""
        # Arrange

        mock_api_keys.hunter_api_key = "invalid_key"
        mock_response = MagicMock(status_code=401)
        mock_get.return_value = mock_response

        # Act

        result = find_employee_emails("example.com")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Invalid Hunter.io API key", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.personnel_osint.find_employee_emails")
    def test_cli_emails_with_argument(self, mock_find_emails):
        """Tests the 'personnel-osint emails' command with a direct argument."""
        # Arrange

        mock_find_emails.return_value = PersonnelOSINTResult(
            domain="example.com", total_emails_found=5
        )

        # Act

        result = runner.invoke(personnel_osint_app, ["emails", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_find_emails.assert_called_with("example.com")
        output = json.loads(result.stdout)
        self.assertEqual(output["domain"], "example.com")
        self.assertEqual(output["total_emails_found"], 5)

    @patch("chimera_intel.core.personnel_osint.get_active_project")
    @patch("chimera_intel.core.personnel_osint.find_employee_emails")
    def test_cli_emails_with_project(self, mock_find_emails, mock_get_project):
        """Tests the CLI command using an active project's domain."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="Test", created_at="", domain="project.com"
        )
        mock_get_project.return_value = mock_project
        mock_find_emails.return_value = PersonnelOSINTResult(domain="project.com")

        # Act

        result = runner.invoke(personnel_osint_app, ["emails"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Using domain 'project.com' from active project", result.stdout)
        mock_find_emails.assert_called_with("project.com")

    def test_cli_emails_invalid_domain(self):
        """Tests the CLI command with an invalid domain."""
        result = runner.invoke(personnel_osint_app, ["emails", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)


if __name__ == "__main__":
    unittest.main()
