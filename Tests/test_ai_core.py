"""
Unit tests for the 'ai_core' module.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
from typer.testing import CliRunner
from chimera_intel.cli import app  # Import the main Typer app
from chimera_intel.core.ai_core import (
    analyze_sentiment,
    generate_swot_from_data,
    detect_traffic_anomalies,
)

runner = CliRunner()


class TestAiCore(unittest.TestCase):
    """Test cases for core AI analysis functions."""

    @patch("chimera_intel.core.ai_core.sentiment_analyzer")
    def test_analyze_sentiment_positive(self, mock_analyzer: MagicMock):
        """Tests the sentiment analysis function with a mocked positive result."""
        mock_analyzer.return_value = [{"label": "POSITIVE", "score": 0.99}]
        result = analyze_sentiment("This is great!")
        self.assertEqual(result.label, "POSITIVE")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.ai_core.sentiment_analyzer")
    def test_analyze_sentiment_failure(self, mock_analyzer: MagicMock):
        """Tests the sentiment analysis function when the model raises an exception."""
        mock_analyzer.side_effect = Exception("Model loading failed")
        result = analyze_sentiment("Some text")
        self.assertEqual(result.label, "ERROR")
        self.assertIn("Model loading failed", result.error)

    def test_analyze_sentiment_no_model(self):
        """Tests sentiment analysis when the 'transformers' library is not available."""
        with patch("chimera_intel.core.ai_core.sentiment_analyzer", None):
            result = analyze_sentiment("Some text")
            self.assertEqual(result.label, "ERROR")
            self.assertIn("not installed", result.error)

    @patch("chimera_intel.core.ai_core.genai")
    def test_generate_swot_from_data_success(self, mock_genai: MagicMock):
        """Tests a successful SWOT analysis generation."""
        mock_model_instance = mock_genai.GenerativeModel.return_value
        mock_model_instance.generate_content.return_value.text = "## SWOT Analysis"
        result = generate_swot_from_data('{"key": "value"}', "fake_google_key")
        self.assertEqual(result.analysis_text, "## SWOT Analysis")
        self.assertIsNone(result.error)
        mock_genai.configure.assert_called_with(api_key="fake_google_key")

    @patch("chimera_intel.core.ai_core.genai")
    def test_generate_swot_from_data_api_error(self, mock_genai: MagicMock):
        """Tests SWOT generation when the Google AI API returns an error."""
        mock_model_instance = mock_genai.GenerativeModel.return_value
        mock_model_instance.generate_content.side_effect = Exception(
            "API limit reached"
        )
        result = generate_swot_from_data('{"key": "value"}', "fake_google_key")
        self.assertIn("API limit reached", result.error)
        self.assertEqual(result.analysis_text, "")

    def test_generate_swot_from_data_no_key(self):
        """Tests SWOT generation when the Google API key is missing."""
        result = generate_swot_from_data("{}", "")
        self.assertIn("not found", result.error)

    def test_detect_traffic_anomalies_success(self):
        """Tests anomaly detection with a sample dataset containing an anomaly."""
        traffic_data = [100.0, 105.0, 110.0, 500.0, 98.0]
        result = detect_traffic_anomalies(traffic_data)
        self.assertIn(500.0, result.detected_anomalies)
        self.assertIsNone(result.error)

    def test_detect_traffic_anomalies_invalid_data(self):
        """Tests anomaly detection with invalid (non-numeric) data."""
        invalid_data = [100.0, "not a number", 110.0]
        result = detect_traffic_anomalies(invalid_data)
        self.assertIn("Invalid input", result.error)

    def test_detect_traffic_anomalies_no_sklearn(self):
        """Tests anomaly detection when 'scikit-learn' is not available."""
        with patch("chimera_intel.core.ai_core.IsolationForest", None):
            result = detect_traffic_anomalies([100.0, 110.0])
            self.assertIn("not installed", result.error)

    # --- NEW TESTS FOR CLI COMMANDS ---

    @patch("chimera_intel.core.ai_core.analyze_sentiment")
    def test_cli_sentiment_command(self, mock_analyze):
        """Tests the 'sentiment' CLI command."""
        mock_analyze.return_value.model_dump.return_value = {
            "label": "POSITIVE",
            "score": 0.9,
        }
        result = runner.invoke(app, ["analysis", "sentiment", "I love this!"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"label": "POSITIVE"', result.stdout)

    @patch("builtins.open", new_callable=mock_open, read_data='{"data": "test"}')
    @patch("chimera_intel.core.ai_core.generate_swot_from_data")
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_key")
    def test_cli_swot_command(self, mock_swot, mock_file):
        """Tests the 'swot' CLI command."""
        mock_swot.return_value.analysis_text = "SWOT Text"
        mock_swot.return_value.error = None
        result = runner.invoke(app, ["analysis", "swot", "input.json"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("SWOT Text", result.stdout)

    @patch("builtins.open", side_effect=FileNotFoundError)
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_key")
    def test_cli_swot_command_file_not_found(self, mock_open):
        """Tests the 'swot' command when the input file is not found."""
        result = runner.invoke(app, ["analysis", "swot", "nonexistent.json"])
        # The command should not crash but log an error (exit_code 0)

        self.assertEqual(result.exit_code, 0)

    @patch("chimera_intel.core.ai_core.detect_traffic_anomalies")
    def test_cli_anomaly_command(self, mock_detect):
        """Tests the 'anomaly' CLI command."""
        mock_detect.return_value.model_dump.return_value = {
            "detected_anomalies": [500.0]
        }
        result = runner.invoke(app, ["analysis", "anomaly", "100,200,500"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"detected_anomalies":', result.stdout)

    def test_cli_anomaly_command_invalid_data(self):
        """Tests the 'anomaly' command with invalid data."""
        result = runner.invoke(app, ["analysis", "anomaly", "a,b,c"])
        # The command should not crash but log an error (exit_code 0)

        self.assertEqual(result.exit_code, 0)
        # There should be no output as the error is logged

        self.assertNotIn('"detected_anomalies":', result.stdout)


if __name__ == "__main__":
    unittest.main()
