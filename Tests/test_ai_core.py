import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.ai_core import analyze_sentiment, detect_traffic_anomalies

class TestAiCore(unittest.TestCase):

    @patch('chimera_intel.core.ai_core.sentiment_analyzer')
    def test_analyze_sentiment(self, mock_analyzer):
        # Simulate a sentiment analysis result
        mock_analyzer.return_value = [{'label': 'POSITIVE', 'score': 0.99}]
        result = analyze_sentiment("This is great!")
        self.assertEqual(result['label'], 'POSITIVE')

    def test_detect_traffic_anomalies(self):
        # This function has no external dependencies, so we test it directly.
        # An obvious anomaly is added to the data.
        traffic_data = [100, 105, 110, 102, 108, 500, 98, 112]
        result = detect_traffic_anomalies(traffic_data)
        self.assertIn(500, result["detected_anomalies"])
        self.assertNotIn(100, result["detected_anomalies"])

if __name__ == '__main__':
    unittest.main()