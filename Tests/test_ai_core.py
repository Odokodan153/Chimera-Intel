"""
Unit tests for the 'ai_core' module.

This test suite verifies the functionality of the AI analysis functions
in 'chimera_intel.core.ai_core.py'. It uses 'unittest.mock' to simulate
the behavior of the AI models, ensuring that the tests are fast and do not
require loading large models or making external API calls.
"""

import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.ai_core import (
    analyze_sentiment,
    generate_swot_from_data,
    detect_traffic_anomalies,
)


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

    # FIX: Patched the entire 'genai' module instead of an attribute on it.

    @patch("chimera_intel.core.ai_core.genai")
    def test_generate_swot_from_data_success(self, mock_genai: MagicMock):
        """Tests a successful SWOT analysis generation."""
        # Configure the mock object that the patch provides

        mock_model_instance = mock_genai.GenerativeModel.return_value
        mock_model_instance.generate_content.return_value.text = "## SWOT Analysis"

        result = generate_swot_from_data('{"key": "value"}', "fake_google_key")
        self.assertEqual(result.analysis_text, "## SWOT Analysis")
        self.assertIsNone(result.error)
        # Verify that configure was called

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


if __name__ == "__main__":
    unittest.main()
