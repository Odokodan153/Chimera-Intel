import unittest
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.weak_signal_analyzer import (
    generate_weak_signals,
    amplify_signals_with_dempster_shafer,
    wsa_app,
)
from chimera_intel.core.schemas import AmplifiedEventResult, WeakSignal

runner = CliRunner()


class TestWeakSignalAnalyzer(unittest.TestCase):
    """Test cases for the Weak Signal Amplification (WSA) module."""

    # --- Function Tests ---

    def test_generate_weak_signals(self):
        """Tests the generation of weak signals from aggregated data."""
        # Arrange

        aggregated_data = {
            "modules": {
                "business_intel": {
                    "news": {"totalArticles": 25},
                    "financials": {"trailingPE": 10},
                }
            }
        }

        # Act

        signals = generate_weak_signals(aggregated_data)

        # Assert

        self.assertEqual(len(signals), 2)
        self.assertTrue(all(s.signal_type == "MergerOrAcquisition" for s in signals))

    def test_amplify_signals_with_dempster_shafer_success(self):
        """Tests the successful amplification of signals using Dempster-Shafer."""
        # Arrange

        signals = [
            WeakSignal(
                source_module="test1",
                signal_type="HypothesisA",
                description="Signal 1",
                belief=0.3,
            ),
            WeakSignal(
                source_module="test2",
                signal_type="HypothesisA",
                description="Signal 2",
                belief=0.4,
            ),
        ]

        # Expected combined belief: 0.3 + 0.4 - (0.3 * 0.4) = 0.58

        # Act

        amplified_events = amplify_signals_with_dempster_shafer(signals)

        # Assert

        self.assertEqual(len(amplified_events), 1)
        self.assertEqual(amplified_events[0].event_hypothesis, "HypothesisA")
        self.assertAlmostEqual(amplified_events[0].combined_belief, 0.58)

    def test_amplify_signals_no_amplification_for_single_signal(self):
        """Tests that no amplification occurs if there's only one signal for a hypothesis."""
        signals = [
            WeakSignal(
                source_module="test1",
                signal_type="HypothesisA",
                description="Signal 1",
                belief=0.3,
            )
        ]
        amplified_events = amplify_signals_with_dempster_shafer(signals)
        self.assertEqual(len(amplified_events), 0)

    # --- CLI Tests ---

    @patch("chimera_intel.core.weak_signal_analyzer.resolve_target")
    @patch("chimera_intel.core.weak_signal_analyzer.get_aggregated_data_for_target")
    @patch(
        "chimera_intel.core.weak_signal_analyzer.amplify_signals_with_dempster_shafer"
    )
    @patch("chimera_intel.core.weak_signal_analyzer.save_scan_to_db")
    def test_cli_run_wsa_analysis_success(
        self, mock_save_scan, mock_amplify, mock_get_data, mock_resolve
    ):
        """Tests a successful run of the 'wsa run' CLI command."""
        # Arrange

        mock_resolve.return_value = "example.com"
        mock_get_data.return_value = {"modules": {}}
        mock_amplify.return_value = [
            AmplifiedEventResult(
                event_hypothesis="Test Event",
                combined_belief=0.8,
                contributing_signals=[],
                summary="This is a test summary.",
            )
        ]

        # Act

        result = runner.invoke(wsa_app, ["run", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Amplified Intelligence Events", result.stdout)
        self.assertIn("Hypothesis: Test Event", result.stdout)
        self.assertIn("Combined Belief: 80.0%", result.stdout)

    @patch("chimera_intel.core.weak_signal_analyzer.resolve_target")
    @patch(
        "chimera_intel.core.weak_signal_analyzer.get_aggregated_data_for_target",
        return_value=None,
    )
    def test_cli_run_no_historical_data(self, mock_get_data, mock_resolve):
        """Tests the CLI command when no historical data is found."""
        # Arrange

        mock_resolve.return_value = "example.com"

        # Act

        result = runner.invoke(wsa_app, ["run", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No historical data", result.stdout)


if __name__ == "__main__":
    unittest.main()
