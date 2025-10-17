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
    """Test cases for the PESTEL Analysis module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.pestel_analyzer.generate_swot_from_data")
    @patch("chimera_intel.core.pestel_analyzer.API_KEYS")
    def test_generate_pestel_analysis_success(self, mock_api_keys, mock_gen_swot):
        """Tests successful PESTEL analysis generation."""
        # Arrange

        mock_api_keys.google_api_key = "fake_key"
        mock_gen_swot.return_value = SWOTAnalysisResult(analysis_text="## Political")
        aggregated_data = {"target": "example.com", "modules": {}}

        # Act

        result = generate_pestel_analysis(aggregated_data, "fake_key")

        # Assert

        self.assertIsInstance(result, PESTELAnalysisResult)
        self.assertIsNone(result.error)
        self.assertIn("Political", result.analysis_text)
        mock_gen_swot.assert_called_once()
        prompt_arg = mock_gen_swot.call_args[0][0]
        self.assertIn("PESTEL", prompt_arg)
        # Corrected assertion to be whitespace-insensitive

        self.assertIn(
            "(Political, Economic, Social, Technological, Environmental, Legal)",
            " ".join(prompt_arg.split()),
        )

    def test_generate_pestel_analysis_no_api_key(self):
        """Tests PESTEL analysis generation when the API key is missing."""
        result = generate_pestel_analysis({}, "")
        self.assertIsNotNone(result.error)
        self.assertIn("GOOGLE_API_KEY not found", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.pestel_analyzer.generate_pestel_analysis")
    @patch("chimera_intel.core.pestel_analyzer.get_aggregated_data_for_target")
    @patch("chimera_intel.core.pestel_analyzer.resolve_target")
    @patch("chimera_intel.core.pestel_analyzer.API_KEYS")
    def test_cli_run_pestel_analysis_success(
        self, mock_api_keys, mock_resolve, mock_get_data, mock_generate
    ):
        """Tests a successful run of the 'pestel-analyzer run' command."""
        # Arrange

        mock_api_keys.google_api_key = "fake_key"
        mock_resolve.return_value = "example.com"
        mock_get_data.return_value = {"target": "example.com"}
        mock_generate.return_value = PESTELAnalysisResult(
            analysis_text="### PESTEL Analysis"
        )

        # Act

        result = runner.invoke(pestel_analyzer_app, ["run", "--target", "example.com"])
        # Assert

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("PESTEL Analysis for example.com", result.stdout)
        self.assertIn("PESTEL Analysis", result.stdout)
        mock_generate.assert_called_with({"target": "example.com"}, "fake_key")

    @patch("chimera_intel.core.pestel_analyzer.resolve_target")
    @patch(
        "chimera_intel.core.pestel_analyzer.get_aggregated_data_for_target",
        return_value=None,
    )
    @patch("chimera_intel.core.pestel_analyzer.API_KEYS")
    def test_cli_run_no_historical_data(
        self, mock_api_keys, mock_get_data, mock_resolve
    ):
        """Tests the CLI command when no historical data is found."""
        # Arrange

        mock_api_keys.google_api_key = "fake_key"
        mock_resolve.return_value = "example.com"

        # Act

        result = runner.invoke(pestel_analyzer_app, ["run", "--target", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 1, result.stdout)
        self.assertIn("No historical data found", result.stdout)
