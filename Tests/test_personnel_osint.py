import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError
from typer.testing import CliRunner

# Import the specific Typer app for this module, not the main one


from chimera_intel.core.personnel_osint import personnel_osint_app
from chimera_intel.core.personnel_osint import find_employee_emails
from chimera_intel.core.schemas import PersonnelOSINTResult, ProjectConfig

runner = CliRunner()


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

    @patch("chimera_intel.core.personnel_osint.find_employee_emails")
    def test_cli_personnel_emails_success(self, mock_find_emails):
        """Tests the 'personnel emails' CLI command successfully with an explicit domain."""
        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "domain": "example.com",
            "total_emails_found": 1,
        }
        mock_find_emails.return_value = mock_result

        # FIX: The command is 'emails', and the argument is the domain.

        result = runner.invoke(personnel_osint_app, ["example.com"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_emails_found": 1', result.stdout)
        mock_find_emails.assert_called_with("example.com")

    def test_cli_personnel_emails_invalid_domain(self):
        """Tests the 'personnel emails' CLI command with an invalid domain."""
        # FIX: Correctly pass the invalid domain as an argument.

        result = runner.invoke(personnel_osint_app, ["invalid-domain"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("is not a valid domain format", result.stdout)

    @patch("chimera_intel.core.personnel_osint.sync_client.get")
    def test_find_employee_emails_http_error(self, mock_get):
        """Tests exception handling for HTTP errors."""
        mock_get.side_effect = RequestError("Network error")
        with patch(
            "chimera_intel.core.config_loader.API_KEYS.hunter_api_key", "fake_key"
        ):
            result = find_employee_emails("example.com")
            self.assertIsNotNone(result.error)

    # --- NEW: Project-Aware CLI Tests ---

    @patch("chimera_intel.core.personnel_osint.get_active_project")
    @patch("chimera_intel.core.personnel_osint.find_employee_emails")
    def test_cli_emails_with_active_project(self, mock_find_emails, mock_get_project):
        """Tests the CLI command using an active project's context."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="PersonnelTest",
            created_at="2025-01-01",
            domain="project-domain.com",
        )
        mock_get_project.return_value = mock_project

        mock_result = MagicMock()
        mock_result.model_dump.return_value = {
            "domain": "project-domain.com",
            "total_emails_found": 5,
        }
        mock_find_emails.return_value = mock_result

        # Act: Run command without an explicit domain
        # FIX: Invoking with an empty list correctly simulates omitting the optional argument.

        result = runner.invoke(personnel_osint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Using domain 'project-domain.com' from active project", result.stdout
        )
        mock_find_emails.assert_called_with("project-domain.com")

    @patch("chimera_intel.core.personnel_osint.get_active_project")
    def test_cli_emails_no_domain_no_project(self, mock_get_project):
        """Tests the CLI fails when no domain is provided and no active project is active."""
        # Arrange

        mock_get_project.return_value = None

        # Act
        # FIX: Correct invocation when no argument is provided.

        result = runner.invoke(personnel_osint_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No domain provided and no active project set", result.stdout)


if __name__ == "__main__":
    unittest.main()
