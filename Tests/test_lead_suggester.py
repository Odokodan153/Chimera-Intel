import unittest
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.lead_suggester import (
    generate_lead_suggestions,
    lead_suggester_app,
)
from chimera_intel.core.schemas import (
    LeadSuggestionResult,
    SWOTAnalysisResult,
    ProjectConfig,
)

runner = CliRunner()


class TestLeadSuggester(unittest.TestCase):
    """Test cases for the Lead Suggester module."""

    @patch("chimera_intel.core.lead_suggester.generate_swot_from_data")
    def test_generate_lead_suggestions_success(self, mock_ai_generate):
        """Tests a successful lead suggestion generation."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="### Suggested Leads"
        )
        test_data = {"target": "example.com", "modules": {}}

        # Act

        result = generate_lead_suggestions(test_data, "fake_google_key")

        # Assert

        self.assertIsInstance(result, LeadSuggestionResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.suggestions_text, "### Suggested Leads")
        mock_ai_generate.assert_called_once()

    def test_generate_lead_suggestions_no_api_key(self):
        """Tests that the function returns an error if no API key is provided."""
        # Act

        result = generate_lead_suggestions({}, "")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("GOOGLE_API_KEY not found", result.error)

    @patch("chimera_intel.core.lead_suggester.generate_swot_from_data")
    def test_generate_lead_suggestions_api_error(self, mock_ai_generate):
        """Tests error handling when the AI generation function fails."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="", error="API error"
        )

        # Act

        result = generate_lead_suggestions({}, "fake_google_key")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the Google AI API", result.error)

    @patch("chimera_intel.core.lead_suggester.get_active_project")
    @patch("chimera_intel.core.lead_suggester.get_aggregated_data_for_target")
    @patch("chimera_intel.core.lead_suggester.generate_lead_suggestions")
    def test_cli_lead_suggester_success(
        self, mock_generate, mock_get_data, mock_get_project
    ):
        """Tests the 'suggest-leads' CLI command with a successful run."""
        mock_get_project.return_value = ProjectConfig(
            project_name="Test",
            created_at="",
            company_name="TestCorp",
            domain="test.com",
        )
        mock_get_data.return_value = {"target": "TestCorp", "modules": {}}
        mock_generate.return_value = LeadSuggestionResult(
            suggestions_text="**Test Suggestions**"
        )
        with patch(
            "chimera_intel.core.lead_suggester.API_KEYS.google_api_key", "fake_key"
        ):
            result = runner.invoke(lead_suggester_app, [])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Test Suggestions", result.stdout)

    @patch("chimera_intel.core.lead_suggester.get_active_project", return_value=None)
    def test_cli_lead_suggester_no_active_project(self, mock_get_project):
        """Tests the CLI command when no active project is set."""
        result = runner.invoke(lead_suggester_app, [])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No active project set", result.stdout)
