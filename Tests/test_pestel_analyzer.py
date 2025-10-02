import unittest
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.pestel_analyzer import (
    generate_pestel_analysis,
    pestel_analyzer_app,
)
from chimera_intel.core.schemas import PESTELAnalysisResult, SWOTAnalysisResult

runner = CliRunner()


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

    @patch("chimera_intel.core.pestel_analyzer.resolve_target")
    @patch("chimera_intel.core.pestel_analyzer.get_aggregated_data_for_target")
    @patch("chimera_intel.core.pestel_analyzer.generate_pestel_analysis")
    def test_cli_pestel_analysis_success(
        self, mock_generate, mock_get_data, mock_resolve_target
    ):
        """Tests the 'pestel' CLI command with a successful run."""
        mock_resolve_target.return_value = "test.com"
        mock_get_data.return_value = {"target": "test.com", "modules": {}}
        mock_generate.return_value = PESTELAnalysisResult(
            analysis_text="**Test PESTEL**"
        )
        with patch(
            "chimera_intel.core.pestel_analyzer.API_KEYS.google_api_key", "fake_key"
        ):
            result = runner.invoke(pestel_analyzer_app, ["test.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Test PESTEL", result.stdout)

    @patch("chimera_intel.core.pestel_analyzer.resolve_target")
    @patch(
        "chimera_intel.core.pestel_analyzer.get_aggregated_data_for_target",
        return_value=None,
    )
    def test_cli_pestel_analysis_no_data(self, mock_get_data, mock_resolve_target):
        """Tests the CLI command when no historical data is found."""
        mock_resolve_target.return_value = "test.com"
        result = runner.invoke(pestel_analyzer_app, ["test.com"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No historical data found", result.stdout)
