import unittest
from unittest.mock import patch

from chimera_intel.core.lead_suggester import generate_lead_suggestions
from chimera_intel.core.schemas import LeadSuggestionResult, SWOTAnalysisResult


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


if __name__ == "__main__":
    unittest.main()
