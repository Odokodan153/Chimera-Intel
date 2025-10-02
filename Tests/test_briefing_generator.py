import unittest
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.briefing_generator import (
    generate_intelligence_briefing,
    present_app,
)
from chimera_intel.core.schemas import BriefingResult, SWOTAnalysisResult, ProjectConfig

runner = CliRunner()


class TestBriefingGenerator(unittest.TestCase):
    """Test cases for the Briefing Generator module."""

    @patch("chimera_intel.core.briefing_generator.generate_swot_from_data")
    def test_generate_intelligence_briefing_success(self, mock_ai_generate):
        """Tests a successful intelligence briefing generation."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="## Executive Summary"
        )
        test_data = {"target": "example.com", "modules": {}}

        # Act

        result = generate_intelligence_briefing(test_data, "fake_google_key")

        # Assert

        self.assertIsInstance(result, BriefingResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.briefing_text, "## Executive Summary")
        mock_ai_generate.assert_called_once()

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

    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch("chimera_intel.core.briefing_generator.get_aggregated_data_for_target")
    @patch("chimera_intel.core.briefing_generator.generate_intelligence_briefing")
    def test_cli_briefing_success(self, mock_generate, mock_get_data, mock_get_project):
        """Tests the 'briefing' CLI command with a successful run."""
        mock_get_project.return_value = ProjectConfig(
            project_name="Test",
            created_at="",
            company_name="TestCorp",
            domain="test.com",
        )
        mock_get_data.return_value = {"target": "TestCorp", "modules": {}}
        mock_generate.return_value = BriefingResult(briefing_text="**Test Briefing**")
        with patch(
            "chimera_intel.core.briefing_generator.API_KEYS.google_api_key", "fake_key"
        ):
            result = runner.invoke(present_app, [])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Test Briefing", result.stdout)

    @patch(
        "chimera_intel.core.briefing_generator.get_active_project", return_value=None
    )
    def test_cli_briefing_no_active_project(self, mock_get_project):
        """Tests the CLI command when no active project is set."""
        result = runner.invoke(present_app, [])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No active project set", result.stdout)

    @patch("chimera_intel.core.briefing_generator.get_active_project")
    def test_cli_briefing_no_target_in_project(self, mock_get_project):
        """Tests the CLI command when the active project has no target."""
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", created_at=""
        )
        result = runner.invoke(present_app, [])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Active project has no target", result.stdout)

    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch(
        "chimera_intel.core.briefing_generator.get_aggregated_data_for_target",
        return_value=None,
    )
    def test_cli_briefing_no_historical_data(self, mock_get_data, mock_get_project):
        """Tests the CLI command when no historical data is found for the target."""
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", created_at="", domain="test.com"
        )
        result = runner.invoke(present_app, [])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No historical data found", result.stdout)

    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch("chimera_intel.core.briefing_generator.get_aggregated_data_for_target")
    def test_cli_briefing_no_api_key(self, mock_get_data, mock_get_project):
        """Tests the CLI command when the Google API key is missing."""
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", created_at="", domain="test.com"
        )
        mock_get_data.return_value = {"target": "test.com", "modules": {}}
        with patch(
            "chimera_intel.core.briefing_generator.API_KEYS.google_api_key", None
        ):
            result = runner.invoke(present_app, [])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Google API key (GOOGLE_API_KEY) not found", result.stdout)

    @patch("chimera_intel.core.briefing_generator.get_active_project")
    @patch("chimera_intel.core.briefing_generator.get_aggregated_data_for_target")
    @patch("chimera_intel.core.briefing_generator.generate_intelligence_briefing")
    def test_cli_briefing_generation_error(
        self, mock_generate, mock_get_data, mock_get_project
    ):
        """Tests the CLI command when the AI generation fails."""
        mock_get_project.return_value = ProjectConfig(
            project_name="Test", created_at="", domain="test.com"
        )
        mock_get_data.return_value = {"target": "test.com", "modules": {}}
        mock_generate.return_value = BriefingResult(briefing_text="", error="AI error")
        with patch(
            "chimera_intel.core.briefing_generator.API_KEYS.google_api_key", "fake_key"
        ):
            result = runner.invoke(present_app, [])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Error generating briefing", result.stdout)
