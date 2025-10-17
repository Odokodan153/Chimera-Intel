import unittest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from rich.panel import Panel

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

    @patch("chimera_intel.core.personnel_osint.console.print")
    @patch("chimera_intel.core.personnel_osint.save_scan_to_db")
    @patch("chimera_intel.core.personnel_osint.save_or_print_results")
    @patch("chimera_intel.core.personnel_osint.find_employee_emails")
    def test_cli_emails_with_argument(
        self, mock_find_emails, mock_save_results, mock_save_db, mock_console
    ):
        """Tests the 'personnel-osint emails' command with a direct argument."""
        # Arrange

        mock_find_emails.return_value = PersonnelOSINTResult(
            domain="example.com", total_emails_found=5, employee_profiles=[]
        )

        # Act

        result = runner.invoke(personnel_osint_app, ["emails", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_find_emails.assert_called_with("example.com")
        mock_save_results.assert_called_once()

    @patch("chimera_intel.core.personnel_osint.console.print")
    @patch("chimera_intel.core.personnel_osint.save_scan_to_db")
    @patch("chimera_intel.core.personnel_osint.save_or_print_results")
    @patch("chimera_intel.core.personnel_osint.find_employee_emails")
    @patch("chimera_intel.core.personnel_osint.get_active_project")
    def test_cli_emails_with_project(
        self,
        mock_get_project,
        mock_find_emails,
        mock_save_results,
        mock_save_db,
        mock_console,
    ):
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
        mock_find_emails.assert_called_with("project.com")
        mock_console.assert_any_call(
            "[bold cyan]Using domain 'project.com' from active project 'Test'.[/bold cyan]"
        )

    @patch("chimera_intel.core.personnel_osint.console.print")
    def test_cli_emails_invalid_domain(self, mock_console_print):
        """Tests the CLI command with an invalid domain."""
        result = runner.invoke(personnel_osint_app, ["emails", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)
        mock_console_print.assert_any_call(
            Panel(
                "[bold red]Invalid Input:[/] 'invalid-domain' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )


if __name__ == "__main__":
    unittest.main()
