"""
Unit tests for the 'ai_core' module.

This test suite verifies the functionality of the AI analysis functions
in 'chimera_intel.core.ai_core.py'. It uses 'unittest.mock' to simulate
the behavior of the AI models, ensuring that the tests are fast and do not
require loading large models or making external API calls.
"""

import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.ai_core import analyze_sentiment, detect_traffic_anomalies


class TestAiCore(unittest.TestCase):
    """Test cases for core AI analysis functions."""

    @patch("chimera_intel.core.ai_core.sentiment_analyzer")
    def test_analyze_sentiment_positive(self, mock_analyzer: MagicMock):
        """
        Tests the sentiment analysis function with a mocked transformer model.

        This test simulates a positive sentiment result from the Hugging Face
        pipeline to verify that the wrapper function correctly processes it.

        Args:
            mock_analyzer (MagicMock): A mock for the sentiment analysis pipeline.
        """
        # Simulate a positive sentiment analysis result

        mock_analyzer.return_value = [{"label": "POSITIVE", "score": 0.99}]
        result = analyze_sentiment("This is great!")
        self.assertEqual(result.label, "POSITIVE")
        self.assertIsNone(result.error)

    def test_analyze_sentiment_no_model(self):
        """
        Tests the sentiment analysis function when the model is not available.
        """
        # Use patch as a context manager to temporarily set the analyzer to None

        with patch("chimera_intel.core.ai_core.sentiment_analyzer", None):
            result = analyze_sentiment("Some text")
            self.assertEqual(result.label, "ERROR")
            self.assertIn("not installed", result.error)

    def test_detect_traffic_anomalies_success(self):
        """
        Tests the anomaly detection function with a sample dataset.

        Since this function uses scikit-learn and has no external dependencies,
        it is tested directly with a list containing an obvious anomaly to
        ensure the Isolation Forest model identifies it correctly.
        """
        # An obvious anomaly (500) is added to the data.

        traffic_data = [100.0, 105.0, 110.0, 102.0, 108.0, 500.0, 98.0, 112.0]
        result = detect_traffic_anomalies(traffic_data)
        self.assertIn(500.0, result.detected_anomalies)
        self.assertNotIn(100.0, result.detected_anomalies)
        self.assertIsNone(result.error)

    def test_detect_traffic_anomalies_invalid_data(self):
        """
        Tests anomaly detection with invalid (non-numeric) data.
        """
        # The function should handle non-numeric data gracefully and return an error.

        invalid_data = [100.0, "not a number", 110.0]
        result = detect_traffic_anomalies(invalid_data)
        self.assertEqual(result.detected_anomalies, [])
        self.assertIn("Invalid input", result.error)
        # Check that the original invalid data is returned

        self.assertEqual(result.data_points, invalid_data)

    def test_detect_traffic_anomalies_no_sklearn(self):
        """
        Tests the anomaly detection function when scikit-learn is not installed.
        """
        # Use patch as a context manager to set the library to None

        with patch("chimera_intel.core.ai_core.IsolationForest", None):
            result = detect_traffic_anomalies([100.0, 110.0])
            self.assertEqual(result.detected_anomalies, [])
            self.assertIn("not installed", result.error)


if __name__ == "__main__":
    unittest.main()
