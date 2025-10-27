import unittest
import json
from unittest.mock import patch, MagicMock, mock_open
from typer.testing import CliRunner

# Import the specific Typer app for this module's CLI tests
from chimera_intel.core.ai_core import (
    analyze_sentiment,
    classify_text_zero_shot,  # Import the missing function
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
from chimera_intel.core.graph_schemas import GraphNarrativeResult

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

    # --- Extended Test ---
    @patch("chimera_intel.core.ai_core.classifier")
    def test_classify_text_zero_shot_success(self, mock_classifier):
        """
        Tests the zero-shot classification function.
        """
        mock_classifier.return_value = {"labels": ["urgent"], "scores": [0.9]}
        result = classify_text_zero_shot("This is an urgent matter", ["urgent", "spam"])
        self.assertIsNotNone(result)
        self.assertIn("urgent", result["labels"])

    # --- Extended Test ---
    @patch("chimera_intel.core.ai_core.classifier")
    def test_classify_text_zero_shot_failure(self, mock_classifier):
        """
        Tests the zero-shot classification function when the model fails.
        """
        mock_classifier.side_effect = Exception("Model error")
        result = classify_text_zero_shot("Some text", ["urgent", "spam"])
        self.assertIsNone(result)

    # --- Extended Test ---
    def test_classify_text_zero_shot_no_model(self):
        """
        Tests the zero-shot classification function when the model is not installed.
        """
        with patch("chimera_intel.core.ai_core.classifier", None):
            result = classify_text_zero_shot("Some text", ["urgent", "spam"])
            self.assertIsNone(result)

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
        invalid_data = [100.0, "not a number", 110.0]  # type: ignore
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
        result = runner.invoke(ai_app, ["sentiment", "I love this!"])
        self.assertEqual(result.exit_code, 0)
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
        result = runner.invoke(ai_app, ["swot", "input.json"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("SWOT Text", result.stdout)

    @patch("builtins.open", side_effect=FileNotFoundError)
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_key")
    def test_cli_swot_command_file_not_found(self, mock_open_patch: MagicMock):
        """
        Tests the 'swot' command when the input file is not found.
        """
        result = runner.invoke(ai_app, ["swot", "nonexistent.json"])
        self.assertEqual(result.exit_code, 1)

    # --- Extended Test ---
    @patch("builtins.open", new_callable=mock_open, read_data="invalid json")
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_key")
    def test_cli_swot_command_invalid_json(self, mock_file: MagicMock):
        """
        Tests the 'swot' command when the input file contains invalid JSON.
        """
        result = runner.invoke(ai_app, ["swot", "input.json"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid JSON", result.stdout)

    # --- Extended Test ---
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", None)
    def test_cli_swot_command_no_api_key(self):
        """
        Tests the 'swot' command when the GOOGLE_API_KEY is not set.
        """
        result = runner.invoke(ai_app, ["swot", "input.json"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Google API key not found", result.stdout)

    # --- Extended Test ---
    @patch("builtins.open", new_callable=mock_open, read_data='{"data": "test"}')
    @patch("chimera_intel.core.ai_core.generate_swot_from_data")
    @patch("chimera_intel.core.config_loader.API_KEYS.google_api_key", "fake_key")
    def test_cli_swot_command_api_error(
        self, mock_swot: MagicMock, mock_file: MagicMock
    ):
        """
        Tests the 'swot' CLI command when the underlying function returns an error.
        """
        mock_swot.return_value = SWOTAnalysisResult(
            analysis_text="", error="API Error"
        )
        result = runner.invoke(ai_app, ["swot", "input.json"])
        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.ai_core.detect_traffic_anomalies")
    def test_cli_anomaly_command(self, mock_detect: MagicMock):
        """
        Tests the 'anomaly' CLI command with more specific assertions.
        """
        mock_detect.return_value = AnomalyDetectionResult(
            data_points=[100.0, 200.0, 500.0], detected_anomalies=[500.0]
        )
        result = runner.invoke(ai_app, ["anomaly", "100,200,500"])
        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertIn(500.0, output["detected_anomalies"])
        self.assertEqual(len(output["detected_anomalies"]), 1)

    def test_cli_anomaly_command_invalid_data(self):
        """Tests the 'anomaly' command with invalid data."""
        result = runner.invoke(ai_app, ["anomaly", "a,b,c"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Invalid data points", result.stdout)

    # --- Extended Test ---
    def test_cli_anomaly_command_no_data(self):
        """Tests the 'anomaly' command with no valid data."""
        result = runner.invoke(ai_app, ["anomaly", ", ,"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Invalid data points", result.stdout)

    @patch("chimera_intel.core.ai_core.generate_swot_from_data")
    @patch("chimera_intel.core.ai_core.build_and_save_graph")
    @patch("os.path.exists", return_value=True)
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='{"domain": "example.com", "footprint": {"dns_records": {"A": ["1.2.3.4"]}}}',
    )
    def test_generate_narrative_from_graph_success(
        self, mock_file, mock_exists, mock_build_graph, mock_gen_swot
    ):
        """Tests successful graph narrative generation."""
        mock_gen_swot.return_value = SWOTAnalysisResult(analysis_text="Test narrative")

        result = generate_narrative_from_graph("example.com.json", "fake_api_key")

        self.assertIsInstance(result, GraphNarrativeResult)
        self.assertEqual(result.narrative_text, "Test narrative")
        self.assertIsNone(result.error)
        mock_build_graph.assert_called_once()

    # --- Extended Test ---
    @patch("os.path.exists", return_value=False)
    def test_generate_narrative_from_graph_db_not_found(self, mock_exists):
        """
        Tests narrative generation when the source JSON file doesn't exist.
        """
        result = generate_narrative_from_graph("nonexistent.json", "fake_api_key")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error, "DB error")

    # --- Extended Test ---
    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data="invalid json data")
    def test_generate_narrative_from_graph_json_error(self, mock_file, mock_exists):
        """
        Tests narrative generation when the source JSON file is malformed.
        """
        result = generate_narrative_from_graph("bad.json", "fake_api_key")
        self.assertIsNotNone(result.error)
        # FIX: Check for the content of the error string, not the class name
        self.assertIn("Expecting value", result.error)

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
        mock_gen_swot.return_value = SWOTAnalysisResult(
            analysis_text="", error="API Error"
        )

        result = generate_narrative_from_graph("example.com.json", "fake_api_key")

        self.assertIsNotNone(result.error)
        self.assertIn("API Error", result.error)
        self.assertEqual(result.narrative_text, "")

    def test_detect_traffic_anomalies_empty_list(self):
        """Tests anomaly detection with an empty list."""
        traffic_data = []
        result = detect_traffic_anomalies(traffic_data)
        # An empty list is valid input, it just has no anomalies
        self.assertEqual(result.detected_anomalies, [])
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.ai_core.generate_swot_from_data")
    @patch("chimera_intel.core.ai_core.build_and_save_graph")
    @patch("os.path.exists", return_value=True)
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='{"domain": "example.com", "footprint": {"dns_records": {"A": ["1.2.3.4"]}, "subdomains": {"results": [{"domain": "sub.example.com"}]}}, "web_analysis": {"tech_stack": {"results": [{"technology": "React"}]}}}',
    )
    def test_generate_narrative_from_graph_structure(
        self, mock_file, mock_exists, mock_build_graph, mock_gen_swot
    ):
        """
        Tests that the graph nodes and edges are constructed correctly
        and passed to the SWOT generator.
        """
        mock_gen_swot.return_value = SWOTAnalysisResult(analysis_text="Test narrative")

        result = generate_narrative_from_graph("example.com.json", "fake_api_key")

        self.assertEqual(result.narrative_text, "Test narrative")
        
        # Check that the SWOT function was called with the correct graph data
        self.assertEqual(mock_gen_swot.call_count, 1)
        # Get the second argument (the JSON string) passed to generate_swot_from_data
        prompt_json_str = mock_gen_swot.call_args[0][0] 
        
        self.assertIn('"nodes"', prompt_json_str)
        self.assertIn('"edges"', prompt_json_str)
        
        # Check for specific nodes
        self.assertIn('"id": "example.com"', prompt_json_str)
        self.assertIn('"id": "sub.example.com"', prompt_json_str)
        self.assertIn('"id": "1.2.3.4"', prompt_json_str)
        self.assertIn('"id": "React"', prompt_json_str)
        
        # Check for specific edges
        self.assertIn('"source": "example.com", "target": "sub.example.com", "label": "has_subdomain"', prompt_json_str)
        self.assertIn('"source": "example.com", "target": "1.2.3.4", "label": "resolves_to"', prompt_json_str)
        self.assertIn('"source": "example.com", "target": "React", "label": "uses_tech"', prompt_json_str)


if __name__ == "__main__":
    unittest.main()