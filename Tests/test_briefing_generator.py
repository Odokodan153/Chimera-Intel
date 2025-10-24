import unittest
from unittest.mock import patch, mock_open, MagicMock
from typer.testing import CliRunner
# --- FIX: Import Markdown for assertion ---
from rich.markdown import Markdown

# --- FIX: Import API_KEYS to use with patch.object ---
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.briefing_generator import (
    generate_intelligence_briefing,
    briefing_app,
)
from chimera_intel.core.schemas import BriefingResult, SWOTAnalysisResult, ProjectConfig

# PYTEST_FIX: Instantiate CliRunner with mix_stderr=True
# This captures output from rich.console.print, which often writes to stderr.
runner = CliRunner()


class TestBriefingGenerator(unittest.TestCase):
    """Test cases for the Briefing Generator module."""

    @patch("chimera_intel.core.briefing_generator.generate_swot_from_data")
    def test_generate_intelligence_briefing_success(self, mock_ai_generate):
        """Tests a successful intelligence briefing generation with a valid template."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="## Executive Summary"
        )
        test_data = {"target": "example.com", "modules": {}}

        # Act

        result = generate_intelligence_briefing(
            test_data, "fake_google_key", template="ceo_weekly"
        )

        # Assert

        self.assertIsInstance(result, BriefingResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.briefing_text, "## Executive Summary")
        self.assertEqual(result.title, "CEO Weekly Competitive & Strategic Landscape")
        mock_ai_generate.assert_called_once()

    def test_generate_intelligence_briefing_invalid_template(self):
        """Tests briefing generation with a non-existent template."""
        # Act

        result = generate_intelligence_briefing(
            {}, "fake_google_key", template="non_existent_template"
        )

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Template 'non_existent_template' not found", result.error)

    def test_generate_intelligence_briefing_no_api_key(self):
        """Tests that the function returns an error if no API key is provided."""
        # Act

        result = generate_intelligence_briefing({}, "")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("GOOGLE_API_KEY not found", result.error)

    @patch("chimera_intel.core.briefing_generator.generate_swot_from_data")
    def test_generate_intelligence_briefing_api_error(self, mock_ai_generate):
        """Tests error handling when the AI generation function fails."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="", error="API error"
        )

        # Act

        result = generate_intelligence_briefing({}, "fake_google_key")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the Google AI API", result.error)

    # --- CLI Command Tests (FIXED) ---

    # --- FIX: Changed patch to patch.object(API_KEYS, ...) ---
    @patch.object(API_KEYS, "google_api_key", "fake_key")
    @patch("chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock)
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
        mock_status.return_value.__exit__.return_value = (None, None, None)

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
        # Note: The 'generate' subcommand is removed here because the logic
        # is likely in a Typer 'callback' function, making it the default.
        result = runner.invoke(
            briefing_app, ["--template", "ciso_daily"]
        )

        # Assert
        # Check for exception details if the exit code is not 0
        if result.exit_code != 0:
            print(f"Test Output: {result.stdout}")
            print(f"Test Exception: {result.exception}")

        self.assertEqual(result.exit_code, 0)
        
        # --- FIX: Assert against the mock_print object, not result.stdout ---
        # `console.print` was mocked, so output won't be in `result.stdout`.
        # --- FIX 2: Assert against a Markdown object, not a raw string ---
        mock_print.assert_any_call(Markdown("**Test Briefing**"))
        
        mock_get_project.assert_called_once()
        mock_get_data.assert_called_with("TestCorp")
        mock_generate.assert_called_with(unittest.mock.ANY, "fake_key", "ciso_daily")

    # --- FIX: Changed patch to patch.object(API_KEYS, ...) ---
    @patch.object(API_KEYS, "google_api_key", "fake_key")
    @patch("chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock)
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
        """FIXED: Tests the CLI command with the --output option and verifies file content."""
        # Arrange
        mock_status.return_value.__enter__.return_value = None
        mock_status.return_value.__exit__.return_value = (None, None, None)

        mock_get_project.return_value = ProjectConfig(
            project_name="Test", domain="test.com", created_at="2023-01-01"
        )
        mock_get_data.return_value = {"target": "test.com", "modules": {}}
        mock_generate.return_value = BriefingResult(
            briefing_text="File content", title="File Title"
        )

        with patch("builtins.open", mock_open()) as mock_file:
            # Act
            result = runner.invoke(
                briefing_app, ["--output", "test_briefing.pdf"]
            )

        # Assert
        if result.exit_code != 0:
            print(f"Test Output: {result.stdout}")
            print(f"Test Exception: {result.exception}")

        self.assertEqual(result.exit_code, 0)
        
        # --- FIX: Assert against the mock_print object, not result.stdout ---
        # Check that the "Saved to" message was passed to the mocked print.
        # --- FIX 2: Use a direct assertion instead of complex 'any' loop ---
        mock_print.assert_any_call("[bold green]Briefing saved to:[/bold green] test_briefing.pdf")
        
        mock_file.assert_called_with("test_briefing.pdf", "w")

        # Verify that both the title and the content were written to the file
        mock_file().write.assert_any_call("# File Title\n\n")
        mock_file().write.assert_any_call("File content")

    # --- FIX: Removed the unnecessary and faulty API key patch decorator ---
    @patch("chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock)
    @patch("chimera_intel.core.briefing_generator.console.status")
    @patch(
        "chimera_intel.core.briefing_generator.get_active_project", return_value=None
    )
    def test_cli_briefing_no_active_project(
        self, mock_get_project, mock_status, mock_print
    ):
        """Tests the CLI command when no active project is set."""
        # Arrange
        mock_status.return_value.__enter__.return_value = None
        mock_status.return_value.__exit__.return_value = (None, None, None)

        # Act
        result = runner.invoke(briefing_app, [])

        # Assert
        self.assertEqual(result.exit_code, 1)
        # This assertion is correct, as it checks the mock object.
        mock_print.assert_called_with(
            "[bold red]Error:[/bold red] No active project set. Use 'chimera project use <name>' first."
        )

    # --- FIX: Removed the unnecessary and faulty API key patch decorator ---
    # (The code exits before the API key is checked, so no patch is needed)
    @patch("chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock)
    @patch("chimera_intel.core.briefing_generator.console.status")
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch(
        "chimera_intel.core.briefing_generator.get_aggregated_data_for_target",
        return_value=None,
    )
    def test_cli_briefing_no_historical_data(
        self,
        mock_get_data,
        mock_get_project,
        mock_status,
        mock_print,
    ):
        """FIXED: Tests the CLI command when no historical data is found for the target."""
        # Arrange
        mock_status.return_value.__enter__.return_value = None
        mock_status.return_value.__exit__.return_value = (None, None, None)

        mock_get_project.return_value = ProjectConfig(
            project_name="Test",
            domain="test.com",
            created_at="2023-01-01",
            company_name="Test Inc",
        )

        # Act
        result = runner.invoke(briefing_app, [])

        # Assert
        self.assertEqual(result.exit_code, 1)
        # This assertion is correct.
        mock_print.assert_called_with(
            "[bold red]Error:[/bold red] No historical data found for 'Test Inc'. Run scans first."
        )

    @patch("chimera_intel.core.briefing_generator.console.print", new_callable=MagicMock)
    @patch("chimera_intel.core.briefing_generator.console.status")
    @patch("chimera_intel.core.briefing_generator.get_active_project")
    def test_cli_briefing_no_api_key(
        self, mock_get_project, mock_status, mock_print
    ):
        """FIXED: Tests the CLI command when the Google API key is not configured."""
        # Arrange
        mock_status.return_value.__enter__.return_value = None
        mock_status.return_value.__exit__.return_value = (None, None, None)

        mock_get_project.return_value = ProjectConfig(
            project_name="Test", domain="test.com", created_at="2023-01-01"
        )

        with patch(
            "chimera_intel.core.briefing_generator.get_aggregated_data_for_target",
            return_value={"target": "test.com"},
        ):
            # --- FIX: Changed patch(...) to patch.object(API_KEYS, ...) ---
            with patch.object(
                API_KEYS, "google_api_key", None
            ):
                # Act
                result = runner.invoke(briefing_app, [])
        # Assert
        self.assertEqual(result.exit_code, 1)
        # This assertion is correct.
        mock_print.assert_called_with(
            "[bold red]Error:[/bold red] Google API key (GOOGLE_API_KEY) not found."
        )


if __name__ == "__main__":
    unittest.main()