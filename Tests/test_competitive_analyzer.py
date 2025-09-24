import unittest
from unittest.mock import patch

from chimera_intel.core.competitive_analyzer import generate_competitive_analysis
from chimera_intel.core.schemas import CompetitiveAnalysisResult, SWOTAnalysisResult


class TestCompetitiveAnalyzer(unittest.TestCase):
    """Test cases for the Competitive Analyzer module."""

    @patch("chimera_intel.core.competitive_analyzer.generate_swot_from_data")
    def test_generate_competitive_analysis_success(self, mock_ai_generate):
        """Tests a successful competitive analysis generation."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="## Competitive Analysis"
        )
        target_a_data = {"target": "Company A", "modules": {}}
        target_b_data = {"target": "Company B", "modules": {}}

        # Act

        result = generate_competitive_analysis(
            target_a_data, target_b_data, "fake_google_key"
        )

        # Assert

        self.assertIsInstance(result, CompetitiveAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.analysis_text, "## Competitive Analysis")
        mock_ai_generate.assert_called_once()

    def test_generate_competitive_analysis_no_api_key(self):
        """Tests that the function returns an error if no API key is provided."""
        # Act

        result = generate_competitive_analysis({}, {}, "")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("GOOGLE_API_KEY not found", result.error)

    @patch("chimera_intel.core.competitive_analyzer.generate_swot_from_data")
    def test_generate_competitive_analysis_api_error(self, mock_ai_generate):
        """Tests error handling when the AI generation function fails."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="", error="API error"
        )

        # Act

        result = generate_competitive_analysis({}, {}, "fake_google_key")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the Google AI API", result.error)


if __name__ == "__main__":
    unittest.main()
