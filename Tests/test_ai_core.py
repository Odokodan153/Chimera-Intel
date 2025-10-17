import unittest
import json
from unittest.mock import patch, MagicMock, mock_open
from typer.testing import CliRunner

# Import the specific Typer app for this module's CLI tests


from chimera_intel.core.ai_core import (
    analyze_sentiment,
    generate_swot_from_data,
    detect_traffic_anomalies,
    generate_narrative_from_graph,
    ai_app,  # Import the specific app for direct testing
)
from chimera_intel.core.schemas import (
    SWOTAnalysisResult,
    SentimentAnalysisResult,
    AnomalyDetectionResult,
)
from chimera_intel.core.graph_schemas import GraphNarrativeResult, EntityGraphResult

runner = CliRunner()


class TestAiCore(unittest.TestCase):
    """Test cases for core AI analysis functions."""

    @patch("chimera_intel.core.ai_core.sentiment_analyzer")
    def test_analyze_sentiment_positive(self, mock_analyzer: MagicMock):
        """
        Tests the sentiment analysis function with a mocked positive result.
        """
        mock_analyzer.return_value = [{"label": "POSITIVE", "score": 0.99}]
        result = analyze_sentiment("This is great!")
        self.assertEqual(result.label, "POSITIVE")
        self.assertAlmostEqual(result.score, 0.99)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.ai_core.sentiment_analyzer")
    def test_analyze_sentiment_failure(self, mock_analyzer: MagicMock):
        """
        Tests the sentiment analysis function when the model raises an exception.
        """
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
        """
        Tests a successful SWOT analysis generation.
        """
        mock_model_instance = mock_genai.GenerativeModel.return_value
        mock_model_instance.generate_content.return_value.text = "## SWOT Analysis"

        result = generate_swot_from_data('{"key": "value"}', "fake_google_key")
        self.assertEqual(result.analysis_text, "## SWOT Analysis")
        self.assertIsNone(result.error)
        mock_genai.configure.assert_called_with(api_key="fake_google_key")

    @patch("chimera_intel.core.ai_core.genai")
    def test_generate_swot_from_data_api_error(self, mock_genai: MagicMock):
        """
        Tests SWOT generation when the Google AI API returns an error.
        """
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

    # --- CLI COMMAND TESTS (IMPROVED) ---

    @patch("chimera_intel.core.ai_core.analyze_sentiment")
    def test_cli_sentiment_command(self, mock_analyze: MagicMock):
        """
        Tests the 'sentiment' CLI command with more specific assertions.
        """
        mock_analyze.return_value = SentimentAnalysisResult(label="POSITIVE", score=0.9)
        # CORRECTED: Test the specific Typer app instance for this module

        result = runner.invoke(ai_app, ["sentiment", "I love this!"])
        self.assertEqual(result.exit_code, 0)

        # IMPROVED: Parse the JSON output for more precise testing

        output = json.loads(result.stdout)
        self.assertEqual(output["label"], "POSITIVE")
        self.assertAlmostEqual(output["score"], 0.9)

    @patch("builtins.open", new_callable=mock_open, read_data='{"data": "test"}')
    @patch("chimera_intel.core.ai_core.generate_swot_from_data")
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_key")
    def test_cli_swot_command(self, mock_swot: MagicMock, mock_file: MagicMock):
        """
        Tests the 'swot' CLI command.
        """
        mock_swot.return_value = SWOTAnalysisResult(
            analysis_text="SWOT Text", error=None
        )
        # CORRECTED: Test the specific Typer app instance for this module

        result = runner.invoke(ai_app, ["swot", "input.json"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("SWOT Text", result.stdout)

    @patch("builtins.open", side_effect=FileNotFoundError)
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_key")
    def test_cli_swot_command_file_not_found(self, mock_open_patch: MagicMock):
        """
        Tests the 'swot' command when the input file is not found.
        """
        # CORRECTED: Test the specific Typer app instance for this module

        result = runner.invoke(ai_app, ["swot", "nonexistent.json"])
        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.ai_core.detect_traffic_anomalies")
    def test_cli_anomaly_command(self, mock_detect: MagicMock):
        """
        Tests the 'anomaly' CLI command with more specific assertions.
        """
        mock_detect.return_value = AnomalyDetectionResult(
            data_points=[100.0, 200.0, 500.0], detected_anomalies=[500.0]
        )
        # CORRECTED: Test the specific Typer app instance for this module

        result = runner.invoke(ai_app, ["anomaly", "100,200,500"])
        self.assertEqual(result.exit_code, 0)

        # IMPROVED: Parse the JSON output for more precise testing

        output = json.loads(result.stdout)
        self.assertIn(500.0, output["detected_anomalies"])
        self.assertEqual(len(output["detected_anomalies"]), 1)

    def test_cli_anomaly_command_invalid_data(self):
        """Tests the 'anomaly' command with invalid data."""
        # CORRECTED: Test the specific Typer app instance for this module

        result = runner.invoke(ai_app, ["anomaly", "a,b,c"])
        # Should exit cleanly, but the function inside will handle the error

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Invalid data points", result.stdout)

    # --- EXTENDED LOGIC & EDGE CASES ---

    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", None)
    def test_cli_swot_command_no_api_key(self):
        """
        Tests the 'swot' command when the GOOGLE_API_KEY is not set.
        """
        # CORRECTED: Test the specific Typer app instance for this module

        result = runner.invoke(ai_app, ["swot", "input.json"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Google API key not found", result.stdout)

    @patch("builtins.open", new_callable=mock_open, read_data="invalid json")
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_key")
    def test_cli_swot_command_invalid_json(self, mock_file: MagicMock):
        """
        Tests the 'swot' command when the input file contains invalid JSON.
        """
        # CORRECTED: Test the specific Typer app instance for this module

        result = runner.invoke(ai_app, ["swot", "input.json"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid JSON", result.stdout)

    @patch("chimera_intel.core.ai_core.generate_swot_from_data")
    @patch("chimera_intel.core.ai_core.build_and_save_graph")
    @patch("os.path.exists", return_value=True)
    @patch(
        "builtins.open", new_callable=mock_open, read_data='{"domain": "example.com"}'
    )
    def test_generate_narrative_from_graph_success(
        self, mock_file, mock_exists, mock_build_graph, mock_gen_swot
    ):
        """Tests successful graph narrative generation."""
        mock_build_graph.return_value = EntityGraphResult(
            target="example.com", total_nodes=2, total_edges=1, nodes=[], edges=[]
        )
        mock_gen_swot.return_value = SWOTAnalysisResult(analysis_text="Test narrative")

        result = generate_narrative_from_graph("example.com", "fake_api_key")

        self.assertIsInstance(result, GraphNarrativeResult)
        self.assertEqual(result.narrative_text, "Test narrative")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.ai_core.build_and_save_graph")
    def test_generate_narrative_from_graph_build_error(self, mock_build_graph):
        """Tests graph narrative generation when the graph build fails."""
        mock_build_graph.return_value = EntityGraphResult(
            target="example.com", total_nodes=0, total_edges=0, error="DB error"
        )

        result = generate_narrative_from_graph("example.com", "fake_api_key")

        self.assertIsNotNone(result.error)
        self.assertIn("DB error", result.error)
        self.assertEqual(result.narrative_text, "")

    @patch("chimera_intel.core.ai_core.generate_swot_from_data")
    @patch("chimera_intel.core.ai_core.build_and_save_graph")
    @patch("os.path.exists", return_value=True)
    @patch(
        "builtins.open", new_callable=mock_open, read_data='{"domain": "example.com"}'
    )
    def test_generate_narrative_from_graph_swot_error(
        self, mock_file, mock_exists, mock_build_graph, mock_gen_swot
    ):
        """Tests graph narrative generation when the SWOT analysis fails."""
        mock_build_graph.return_value = EntityGraphResult(
            target="example.com", total_nodes=2, total_edges=1, nodes=[], edges=[]
        )
        mock_gen_swot.return_value = SWOTAnalysisResult(
            analysis_text="", error="API Error"
        )

        result = generate_narrative_from_graph("example.com", "fake_api_key")

        self.assertIsNotNone(result.error)
        self.assertIn("API Error", result.error)
        self.assertEqual(result.narrative_text, "")


if __name__ == "__main__":
    unittest.main()
