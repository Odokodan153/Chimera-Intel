"""
Unit tests for the 'ai_core' module.

This test suite verifies the functionality of the AI analysis functions
in 'chimera_intel.core.ai_core.py'. It uses 'unittest.mock' to simulate
the behavior of the AI models, ensuring that the tests are fast and do not
require loading large models or making external API calls.
"""

import unittest
from unittest.mock import patch
from chimera_intel.core.ai_core import analyze_sentiment, detect_traffic_anomalies


class TestAiCore(unittest.TestCase):
    """Test cases for core AI analysis functions."""

    @patch("chimera_intel.core.ai_core.sentiment_analyzer")
    def test_analyze_sentiment(self, mock_analyzer):
        """
        Tests the sentiment analysis function with a mocked transformer model.

        This test simulates a positive sentiment result from the Hugging Face
        pipeline to verify that the wrapper function correctly processes it.
        """
        # Simulate a sentiment analysis result

        mock_analyzer.return_value = [{"label": "POSITIVE", "score": 0.99}]
        result = analyze_sentiment("This is great!")
        self.assertEqual(result.label, "POSITIVE")

    def test_detect_traffic_anomalies(self):
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


if __name__ == "__main__":
    unittest.main()
