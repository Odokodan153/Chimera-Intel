import unittest
from unittest.mock import patch, mock_open, MagicMock
from typer.testing import CliRunner
from rich.markdown import Markdown

# --- FIX: Import the main app ---
from chimera_intel.cli import get_cli_app

from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.briefing_generator import (
    briefing_app,
)
from chimera_intel.core.schemas import BriefingResult, ProjectConfig

runner = CliRunner()

# --- FIX: Create main app and register the subcommand ---
app = get_cli_app()
app.add_typer(briefing_app, name="briefing")
# --- End Fix ---


class TestBriefingGenerator(unittest.TestCase):
    """Test cases for the Briefing Generator module."""

    # ... (no changes to your non-CLI tests) ...

    # --- CLI Command Tests (FIXED) ---

    @patch.object(API_KEYS, "google_api_key", "fake_key")
    @patch(
        "chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock
    )
    @patch("chimera_intel.core.briefing_generator.console.status")
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch("chimera_intel.core.briefing_generator.get_aggregated_data_for_target")
    @patch("chimera_intel.core.briefing_generator.generate_intelligence_briefing")
    def test_cli_briefing_generate_success(
        self,
        mock_generate,
        mock_get_data,
        mock_get_project,
        mock_status,
        mock_print,
    ):
        """Tests the 'briefing generate' CLI command with a successful run."""
        # Arrange
        mock_status.return_value.__enter__.return_value = None
        mock_get_project.return_value = ProjectConfig(
            project_name="Test",
            company_name="TestCorp",
            domain="test.com",
            created_at="2023-01-01",
        )
        mock_get_data.return_value = {"target": "TestCorp", "modules": {}}
        mock_generate.return_value = BriefingResult(
            briefing_text="**Test Briefing**", title="Test Title"
        )

        # Act
        # --- FIX: Invoke main 'app' with full command 'briefing generate' ---
        result = runner.invoke(
            app, ["briefing", "generate", "--template", "ciso_daily"]
        )
        # --- End Fix ---

        # Assert
        self.assertEqual(result.exit_code, 0, result.exception)

        found_markdown = False
        for call in mock_print.call_args_list:
            arg = call[0][0]
            if isinstance(arg, Markdown):
                if arg.markup == "**Test Briefing**":
                    found_markdown = True
                    break

        self.assertTrue(
            found_markdown, "print was not called with Markdown('**Test Briefing**')"
        )

        mock_get_project.assert_called_once()
        mock_get_data.assert_called_with("TestCorp")
        mock_generate.assert_called_with(unittest.mock.ANY, "fake_key", "ciso_daily")

    @patch.object(API_KEYS, "google_api_key", "fake_key")
    @patch(
        "chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock
    )
    @patch("chimera_intel.core.briefing_generator.console.status")
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch("chimera_intel.core.briefing_generator.get_aggregated_data_for_target")
    @patch("chimera_intel.core.briefing_generator.generate_intelligence_briefing")
    def test_cli_briefing_generate_with_output_file(
        self,
        mock_generate,
        mock_get_data,
        mock_get_project,
        mock_status,
        mock_print,
    ):
        """Tests the CLI command with the --output option and verifies file content."""
        # Arrange
        mock_status.return_value.__enter__.return_value = None
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", domain="test.com", created_at="2023-01-01"
        )
        mock_get_data.return_value = {"target": "test.com", "modules": {}}
        mock_generate.return_value = BriefingResult(
            briefing_text="File content", title="File Title"
        )

        with patch("builtins.open", mock_open()) as mock_file:
            # Act
            # --- FIX: Invoke main 'app' with full command ---
            result = runner.invoke(
                app, ["briefing", "generate", "--output", "test_briefing.pdf"]
            )
            # --- End Fix ---

        # Assert
        self.assertEqual(result.exit_code, 0, result.exception)
        mock_print.assert_any_call(
            "[bold green]Briefing saved to:[/bold green] test_briefing.pdf"
        )
        mock_file.assert_called_with("test_briefing.pdf", "w")
        mock_file().write.assert_any_call("# File Title\n\n")
        mock_file().write.assert_any_call("File content")

    # ... (Apply the same fix to all other CLI tests) ...
    # e.g., runner.invoke(briefing_app, ["generate"])
    #   -> runner.invoke(app, ["briefing", "generate"])

    # e.g., runner.invoke(briefing_app, ["generate", "--output", "test_briefing.pdf"])
    #   -> runner.invoke(app, ["briefing", "generate", "--output", "test_briefing.pdf"])

    @patch(
        "chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock
    )
    @patch(
        "chimera_intel.core.briefing_generator.get_active_project", return_value=None
    )
    def test_cli_briefing_no_active_project(self, mock_get_project, mock_print):
        """Tests the CLI command when no active project is set."""
        # Act
        # --- FIX: Invoke main 'app' with full command ---
        result = runner.invoke(app, ["briefing", "generate"])
        # --- End Fix ---

        # Assert
        self.assertEqual(result.exit_code, 1)
        mock_print.assert_called_with(
            "[bold red]Error:[/bold red] No active project set. Use 'chimera project use <name>' first."
        )

    # --- Extended Test ---
    @patch(
        "chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock
    )
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    def test_cli_briefing_project_no_target(self, mock_get_project, mock_print):
        """Tests CLI error when the active project has no target."""
        # Arrange
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", created_at="2023-01-01", company_name=None, domain=None
        )

        # Act
        # --- FIX: Invoke main 'app' with full command ---
        result = runner.invoke(app, ["briefing", "generate"])
        # --- End Fix ---

        # Assert
        self.assertEqual(result.exit_code, 1)
        mock_print.assert_called_with(
            "[bold red]Error:[/bold red] Active project has no target (domain or company name) set."
        )

    @patch(
        "chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock
    )
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch(
        "chimera_intel.core.briefing_generator.get_aggregated_data_for_target",
        return_value=None,
    )
    def test_cli_briefing_no_historical_data(
        self,
        mock_get_data,
        mock_get_project,
        mock_print,
    ):
        """Tests the CLI command when no historical data is found for the target."""
        # Arrange
        mock_get_project.return_value = ProjectConfig(
            project_name="Test",
            domain="test.com",
            created_at="2023-01-01",
            company_name="Test Inc",
        )

        # Act
        # --- FIX: Invoke main 'app' with full command ---
        result = runner.invoke(app, ["briefing", "generate"])
        # --- End Fix ---

        # Assert
        self.assertEqual(result.exit_code, 1)
        mock_print.assert_called_with(
            "[bold red]Error:[/bold red] No historical data found for 'Test Inc'. Run scans first."
        )

    @patch(
        "chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock
    )
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    def test_cli_briefing_no_api_key(self, mock_get_project, mock_print):
        """Tests the CLI command when the Google API key is not configured."""
        # Arrange
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", domain="test.com", created_at="2023-01-01"
        )

        with patch(
            "chimera_intel.core.briefing_generator.get_aggregated_data_for_target",
            return_value={"target": "test.com"},
        ):
            with patch.object(API_KEYS, "google_api_key", None):
                # Act
                # --- FIX: Invoke main 'app' with full command ---
                result = runner.invoke(app, ["briefing", "generate"])
                # --- End Fix ---
        # Assert
        self.assertEqual(result.exit_code, 1)
        mock_print.assert_called_with(
            "[bold red]Error:[/bold red] Google API key (GOOGLE_API_KEY) not found."
        )

    # --- Extended Test ---
    @patch.object(API_KEYS, "google_api_key", "fake_key")
    @patch(
        "chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock
    )
    @patch("chimera_intel.core.briefing_generator.console.status")
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch("chimera_intel.core.briefing_generator.get_aggregated_data_for_target")
    @patch("chimera_intel.core.briefing_generator.generate_intelligence_briefing")
    def test_cli_briefing_generation_fails(
        self,
        mock_generate,
        mock_get_data,
        mock_get_project,
        mock_status,
        mock_print,
    ):
        """Tests the CLI command when the AI generation itself fails."""
        # Arrange
        mock_status.return_value.__enter__.return_value = None
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", domain="test.com", created_at="2023-01-01"
        )
        mock_get_data.return_value = {"target": "test.com", "modules": {}}
        mock_generate.return_value = BriefingResult(
            briefing_text="", error="AI API limit reached"
        )

        # Act
        # --- FIX: Invoke main 'app' with full command ---
        result = runner.invoke(app, ["briefing", "generate"])
        # --- End Fix ---

        # Assert
        self.assertEqual(result.exit_code, 1)
        mock_print.assert_called_with(
            "[bold red]Error generating briefing:[/bold red] AI API limit reached"
        )

    # --- Extended Test ---
    @patch.object(API_KEYS, "google_api_key", "fake_key")
    @patch(
        "chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock
    )
    @patch("chimera_intel.core.briefing_generator.console.status")
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch("chimera_intel.core.briefing_generator.get_aggregated_data_for_target")
    @patch("chimera_intel.core.briefing_generator.generate_intelligence_briefing")
    def test_cli_briefing_output_file_error(
        self,
        mock_generate,
        mock_get_data,
        mock_get_project,
        mock_status,
        mock_print,
    ):
        """Tests the CLI command when writing to the output file fails."""
        # Arrange
        mock_status.return_value.__enter__.return_value = None
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", domain="test.com", created_at="2023-01-01"
        )
        mock_get_data.return_value = {"target": "test.com", "modules": {}}
        mock_generate.return_value = BriefingResult(
            briefing_text="File content", title="File Title"
        )

        # Simulate a permission error on file open
        with patch("builtins.open", mock_open()) as mock_file:
            mock_file.side_effect = PermissionError("Permission denied")
            # Act
            # --- FIX: Invoke main 'app' with full command ---
            result = runner.invoke(
                app, ["briefing", "generate", "--output", "test_briefing.pdf"]
            )
            # --- End Fix ---

        # Assert
        self.assertEqual(result.exit_code, 1)
        mock_print.assert_called_with(
            "[bold red]Error saving file:[/bold red] Permission denied"
        )


if __name__ == "__main__":
    unittest.main()
