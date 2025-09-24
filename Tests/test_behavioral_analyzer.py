import unittest
from unittest.mock import patch

from chimera_intel.core.behavioral_analyzer import (
    generate_psychographic_profile,
    calculate_narrative_entropy,
)
from chimera_intel.core.schemas import PsychographicProfileResult, BehavioralSignal


class TestBehavioralAnalyzer(unittest.TestCase):
    """Test cases for the behavioral_analyzer module."""

    @patch("chimera_intel.core.behavioral_analyzer.classify_text_zero_shot")
    @patch("chimera_intel.core.behavioral_analyzer.get_aggregated_data_for_target")
    def test_generate_psychographic_profile_success(self, mock_get_data, mock_classify):
        """Tests a successful psychographic profile generation."""
        # Arrange

        mock_get_data.return_value = {
            "modules": {
                "business_intel": {
                    "news": {
                        "articles": [
                            {
                                "title": "New Breakthrough in AI Research",
                                "description": "Our company is leading the future.",
                            }
                        ]
                    }
                }
            }
        }

        # Simulate the AI classifier returning a confident result

        mock_classify.return_value = {
            "labels": ["Innovation & R&D", "Aggressive Marketing"],
            "scores": [0.9, 0.1],
        }

        # Act

        result = generate_psychographic_profile("example.com")

        # Assert

        self.assertIsInstance(result, PsychographicProfileResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.behavioral_signals), 1)
        self.assertEqual(result.behavioral_signals[0].signal_type, "Innovation & R&D")
        self.assertIn("Innovation & R&D", result.profile_summary["dominant_traits"])
        self.assertIsNotNone(result.narrative_entropy)
        mock_classify.assert_called_once()

    def test_calculate_narrative_entropy(self):
        """Tests the narrative entropy calculation."""
        signals = [
            BehavioralSignal(
                source_type="", signal_type="A", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="A", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="B", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="C", content="", justification=""
            ),
        ]
        # P(A) = 0.5, P(B) = 0.25, P(C) = 0.25
        # Entropy = - (0.5*log2(0.5) + 0.25*log2(0.25) + 0.25*log2(0.25)) = 1.5

        entropy_result = calculate_narrative_entropy(signals)
        self.assertIsNotNone(entropy_result)
        self.assertAlmostEqual(entropy_result.entropy_score, 1.5)
        self.assertIn("Focused", entropy_result.assessment)

    @patch("chimera_intel.core.behavioral_analyzer.get_aggregated_data_for_target")
    def test_generate_profile_no_data(self, mock_get_data):
        """Tests the function's response when no historical data is available."""
        # Arrange

        mock_get_data.return_value = None

        # Act

        result = generate_psychographic_profile("nodata.com")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("No historical data found", result.error)


if __name__ == "__main__":
    unittest.main()
