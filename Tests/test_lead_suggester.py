import unittest
from unittest.mock import patch
from typer.testing import CliRunner

# Import API_KEYS from the config loader first
from chimera_intel.core.config_loader import API_KEYS

# --- FIX APPLIED ---
# Patch the API key *before* importing the lead_suggester_app.
# This ensures the Typer app initializes correctly at import time,
# resolving the exit code 2 errors.
with patch.object(API_KEYS, "google_api_key", "fake_key_for_import"):
    from chimera_intel.core.lead_suggester import (
        generate_lead_suggestions,
        lead_suggester_app,
    )
# --- END FIX ---

from chimera_intel.core.schemas import (
    LeadSuggestionResult,
    SWOTAnalysisResult,
    ProjectConfig,
)

runner = CliRunner()


class TestLeadSuggester(unittest.TestCase):
    """Test cases for the AI-Powered Lead Suggester module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.lead_suggester.generate_swot_from_data")
    @patch("chimera_intel.core.lead_suggester.API_KEYS")
    def test_generate_lead_suggestions_success(self, mock_api_keys, mock_gen_swot):
        """Tests successful lead suggestion generation."""
        # Arrange

        # Note: This test patches API_KEYS independently, which is fine.
        mock_api_keys.google_api_key = "fake_key"
        mock_gen_swot.return_value = SWOTAnalysisResult(
            analysis_text="### Lead 1: Investigate Competitor"
        )
        aggregated_data = {"target": "example.com", "modules": {"footprint": {}}}

        # Act

        result = generate_lead_suggestions(aggregated_data, "fake_key")

        # Assert

        self.assertIsInstance(result, LeadSuggestionResult)
        self.assertIsNone(result.error)
        self.assertIn("Investigate Competitor", result.suggestions_text)
        mock_gen_swot.assert_called_once()
        prompt_arg = mock_gen_swot.call_args[0][0]
        self.assertIn("Existing OSINT Data Summary", prompt_arg)

    def test_generate_lead_suggestions_no_api_key(self):
        """Tests lead suggestion generation when the API key is missing."""
        # This test passes an empty string explicitly, so the global
        # patch doesn't affect its logic.
        result = generate_lead_suggestions({}, "")
        self.assertIsNotNone(result.error)
        self.assertIn("GOOGLE_API_KEY not found", result.error)

    @patch("chimera_intel.core.lead_suggester.generate_swot_from_data")
    def test_generate_lead_suggestions_api_error(self, mock_gen_swot):
        """Tests error handling when the AI generation fails."""
        # Arrange

        mock_gen_swot.return_value = SWOTAnalysisResult(
            analysis_text="", error="AI API Error"
        )

        # Act

        result = generate_lead_suggestions({}, "fake_key")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the Google AI API", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.lead_suggester.get_active_project")
    @patch("chimera_intel.core.lead_suggester.get_aggregated_data_for_target")
    @patch("chimera_intel.core.lead_suggester.generate_lead_suggestions")
    def test_cli_run_lead_suggestion_success(
        self, mock_generate, mock_get_data, mock_get_project
    ):
        """Tests a successful run of the 'lead-suggester run' command."""
        # Arrange

        mock_get_project.return_value = ProjectConfig(
            project_name="TestProject",
            company_name="example.com",
            created_at="",
        )
        mock_get_data.return_value = {"target": "example.com"}
        mock_generate.return_value = LeadSuggestionResult(
            suggestions_text="### Suggested Lead"
        )

        # --- FIX APPLIED ---
        # The 'with patch(...)' context manager is removed from here
        # because the API key is now set globally by the import-level patch.
        # --- END FIX ---

        # Act

        result = runner.invoke(lead_suggester_app, ["run", "--no-rich"])
        
        # Assert

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Suggested Lead", result.output)
        # The CLI handler should read the key set at import time
        mock_generate.assert_called_with({"target": "example.com"}, "fake_key_for_import")

    @patch("chimera_intel.core.lead_suggester.get_active_project", return_value=None)
    def test_cli_run_no_active_project(self, mock_get_project):
        """Tests the CLI command when no active project is set."""
        # This test should now fail with exit code 1 instead of 2
        result = runner.invoke(lead_suggester_app, ["run"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No active project set", result.output)

    @patch("chimera_intel.core.lead_suggester.get_active_project")
    @patch(
        "chimera_intel.core.lead_suggester.get_aggregated_data_for_target",
        return_value=None,
    )
    def test_cli_run_no_historical_data(self, mock_get_data, mock_get_project):
        """Tests the CLI command when no historical data is found for the target."""
        # Arrange

        mock_get_project.return_value = ProjectConfig(
            project_name="TestProject",
            company_name="example.com",
            created_at="",
        )

        # Act
        
        # This test should now fail with exit code 1 instead of 2
        result = runner.invoke(lead_suggester_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No historical data found", result.output)


if __name__ == "__main__":
    unittest.main()