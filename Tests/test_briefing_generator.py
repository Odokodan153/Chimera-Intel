import unittest
from unittest.mock import patch

from chimera_intel.core.briefing_generator import generate_intelligence_briefing
from chimera_intel.core.schemas import BriefingResult, SWOTAnalysisResult


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


if __name__ == "__main__":
    unittest.main()
