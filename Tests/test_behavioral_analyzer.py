import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.behavioral_analyzer import (
    generate_psychographic_profile,
    calculate_narrative_entropy,
    behavioral_app,  # Import the Typer app
)
from chimera_intel.core.schemas import PsychographicProfileResult, BehavioralSignal

# Create a runner for CLI tests
runner = CliRunner()


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

    # --- Extended Test ---
    @patch("chimera_intel.core.behavioral_analyzer.classify_text_zero_shot")
    @patch("chimera_intel.core.behavioral_analyzer.get_aggregated_data_for_target")
    def test_generate_profile_with_job_postings(self, mock_get_data, mock_classify):
        """
        Tests profile generation including data from job postings.
        """
        # Arrange
        mock_get_data.return_value = {
            "modules": {
                "job_postings": {
                    "job_postings": [
                        "Senior Growth Hacker",
                        "Data Scientist (R&D)",
                    ]
                }
            }
        }
        # Simulate different classifications for each call
        mock_classify.side_effect = [
            {
                "labels": ["Aggressive Marketing"],
                "scores": [0.8],
            },  # For "Senior Growth Hacker"
            {
                "labels": ["Innovation & R&D"],
                "scores": [0.9],
            },  # For "Data Scientist (R&D)"
        ]

        # Act
        result = generate_psychographic_profile("example.com")

        # Assert
        self.assertIsNone(result.error)
        self.assertEqual(len(result.behavioral_signals), 2)
        self.assertEqual(mock_classify.call_count, 2)
        self.assertEqual(
            result.behavioral_signals[0].signal_type, "Aggressive Marketing"
        )
        self.assertEqual(result.behavioral_signals[1].signal_type, "Innovation & R&D")
        # Check that dominant traits are sorted by count (in this case, 1 each)
        self.assertIn("Aggressive Marketing", result.profile_summary["dominant_traits"])
        self.assertIn("Innovation & R&D", result.profile_summary["dominant_traits"])

    # --- Extended Test ---
    @patch("chimera_intel.core.behavioral_analyzer.classify_text_zero_shot")
    @patch("chimera_intel.core.behavioral_analyzer.get_aggregated_data_for_target")
    def test_generate_profile_low_confidence(self, mock_get_data, mock_classify):
        """
        Tests that signals with low classification confidence are ignored.
        """
        # Arrange
        mock_get_data.return_value = {
            "modules": {
                "business_intel": {"news": {"articles": [{"title": "Vague statement"}]}}
            }
        }
        # Simulate a low confidence score
        mock_classify.return_value = {"labels": ["Innovation & R&D"], "scores": [0.5]}

        # Act
        result = generate_psychographic_profile("example.com")

        # Assert
        self.assertIsNone(result.error)
        # No signal should be created
        self.assertEqual(len(result.behavioral_signals), 0)
        # Profile summary should be empty
        self.assertEqual(len(result.profile_summary["dominant_traits"]), 0)
        # Entropy should be None because there are no signals
        self.assertIsNone(result.narrative_entropy)

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
        # Entropy = 1.5
        entropy_result = calculate_narrative_entropy(signals)
        self.assertIsNotNone(entropy_result)
        self.assertAlmostEqual(entropy_result.entropy_score, 1.5)
        self.assertIn("Focused Narrative (Moderate Entropy)", entropy_result.assessment)
        self.assertEqual(entropy_result.top_keywords, ["A", "B", "C"])

    # --- Extended Test ---
    def test_calculate_narrative_entropy_branches(self):
        """Tests the different assessment branches for entropy."""
        # Low Entropy (< 1.0)
        low_signals = [
            BehavioralSignal(
                source_type="", signal_type="A", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="A", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="A", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="B", content="", justification=""
            ),
        ]  # Entropy = 0.811
        result_low = calculate_narrative_entropy(low_signals)
        self.assertIsNotNone(result_low)
        self.assertLess(result_low.entropy_score, 1.0)
        self.assertIn("Highly Focused Narrative", result_low.assessment)

        # High Entropy (> 2.0)
        high_signals = [
            BehavioralSignal(
                source_type="", signal_type="A", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="B", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="C", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="D", content="", justification=""
            ),
            BehavioralSignal(
                source_type="", signal_type="E", content="", justification=""
            ),
        ]  # Entropy = 2.32
        result_high = calculate_narrative_entropy(high_signals)
        self.assertIsNotNone(result_high)
        self.assertGreater(result_high.entropy_score, 2.0)
        self.assertIn("Diverse Narrative (High Entropy)", result_high.assessment)

    # --- Extended Test ---
    def test_calculate_narrative_entropy_no_signals(self):
        """Tests entropy calculation with no signals."""
        entropy_result = calculate_narrative_entropy([])
        self.assertIsNone(entropy_result)

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

    # --- Extended Test: CLI Commands ---

    @patch("chimera_intel.core.behavioral_analyzer.resolve_target")
    @patch("chimera_intel.core.behavioral_analyzer.generate_psychographic_profile")
    @patch("chimera_intel.core.behavioral_analyzer.save_or_print_results")
    @patch("chimera_intel.core.behavioral_analyzer.save_scan_to_db")
    def test_cli_psych_profile_success(
        self, mock_save_db, mock_save_print, mock_generate, mock_resolve
    ):
        """Tests the 'psych-profile' CLI command."""
        # Arrange
        mock_resolve.return_value = "example.com"
        mock_dump_dict = {"target": "example.com"}
        mock_result = MagicMock(model_dump=lambda exclude_none: mock_dump_dict)
        mock_generate.return_value = mock_result

        # Act
        result = runner.invoke(behavioral_app, ["example.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        mock_resolve.assert_called_with(
            "example.com", required_assets=["domain", "company_name"]
        )
        mock_generate.assert_called_with("example.com")
        mock_save_print.assert_called_with(mock_dump_dict, None)
        mock_save_db.assert_called_with(
            target="example.com", module="behavioral_psych_profile", data=mock_dump_dict
        )

    # --- Extended Test ---
    @patch("chimera_intel.core.behavioral_analyzer.resolve_target")
    @patch("chimera_intel.core.behavioral_analyzer.generate_psychographic_profile")
    @patch("chimera_intel.core.behavioral_analyzer.save_or_print_results")
    @patch("chimera_intel.core.behavioral_analyzer.save_scan_to_db")
    def test_cli_psych_profile_with_output(
        self, mock_save_db, mock_save_print, mock_generate, mock_resolve
    ):
        """Tests the 'psych-profile' CLI command with an --output file."""
        # Arrange
        mock_resolve.return_value = "example.com"
        mock_dump_dict = {"target": "example.com"}
        mock_result = MagicMock(model_dump=lambda exclude_none: mock_dump_dict)
        mock_generate.return_value = mock_result

        # Act
        result = runner.invoke(
            behavioral_app, ["example.com", "--output", "profile.json"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0)
        # Check that save_or_print_results was called with the output file
        mock_save_print.assert_called_with(mock_dump_dict, "profile.json")


if __name__ == "__main__":
    unittest.main()
