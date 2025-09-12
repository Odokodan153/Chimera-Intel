import unittest
from unittest.mock import patch, MagicMock

from chimera_intel.core.pestel_analyzer import generate_pestel_analysis
from chimera_intel.core.schemas import PESTELAnalysisResult, SWOTAnalysisResult


class TestPestelAnalyzer(unittest.TestCase):
    """Test cases for the PESTEL Analyzer module."""

    @patch("chimera_intel.core.pestel_analyzer.generate_swot_from_data")
    def test_generate_pestel_analysis_success(self, mock_ai_generate):
        """Tests a successful PESTEL analysis generation."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="## PESTEL Analysis"
        )
        test_data = {"target": "example.com", "modules": {}}

        # Act

        result = generate_pestel_analysis(test_data, "fake_google_key")

        # Assert

        self.assertIsInstance(result, PESTELAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.analysis_text, "## PESTEL Analysis")
        mock_ai_generate.assert_called_once()

    def test_generate_pestel_analysis_no_api_key(self):
        """Tests that the function returns an error if no API key is provided."""
        # Act

        result = generate_pestel_analysis({}, "")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("GOOGLE_API_KEY not found", result.error)

    @patch("chimera_intel.core.pestel_analyzer.generate_swot_from_data")
    def test_generate_pestel_analysis_api_error(self, mock_ai_generate):
        """Tests error handling when the AI generation function fails."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="", error="API error"
        )

        # Act

        result = generate_pestel_analysis({}, "fake_google_key")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the Google AI API", result.error)


if __name__ == "__main__":
    unittest.main()
