import unittest
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.weak_signal_analyzer import (
    generate_weak_signals,
    amplify_signals_with_dempster_shafer,
    wsa_app,
)
from chimera_intel.core.schemas import WeakSignal, AmplifiedEventResult

runner = CliRunner()


class TestWeakSignalAnalyzer(unittest.TestCase):
    """Test cases for the weak_signal_analyzer module."""

    def test_generate_weak_signals(self):
        """Tests that weak signals are generated correctly from mock data."""
        aggregated_data = {
            "modules": {
                "business_intel": {
                    "news": {"totalArticles": 25},
                    "financials": {"trailingPE": 10},
                },
                "job_postings": {"job_postings": ["Hiring for integration manager"]},
            }
        }
        signals = generate_weak_signals(aggregated_data)
        self.assertEqual(len(signals), 3)

    def test_amplify_signals(self):
        """Tests the Dempster-Shafer combination logic."""
        signals = [
            WeakSignal(source_module="A", signal_type="X", description="", belief=0.3),
            WeakSignal(source_module="B", signal_type="X", description="", belief=0.4),
            WeakSignal(source_module="C", signal_type="X", description="", belief=0.5),
        ]
        amplified_events = amplify_signals_with_dempster_shafer(signals)
        self.assertEqual(len(amplified_events), 1)
        self.assertAlmostEqual(amplified_events[0].combined_belief, 0.79)

    @patch("chimera_intel.core.weak_signal_analyzer.resolve_target")
    @patch("chimera_intel.core.weak_signal_analyzer.get_aggregated_data_for_target")
    @patch("chimera_intel.core.weak_signal_analyzer.generate_weak_signals")
    @patch(
        "chimera_intel.core.weak_signal_analyzer.amplify_signals_with_dempster_shafer"
    )
    def test_cli_wsa_run_no_events(
        self, mock_amplify, mock_generate, mock_get_data, mock_resolve
    ):
        """Tests the CLI command when no amplified events are found."""
        mock_resolve.return_value = "example.com"
        mock_get_data.return_value = {"modules": {}}
        mock_generate.return_value = []
        mock_amplify.return_value = []

        result = runner.invoke(wsa_app, ["run"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("No combination of weak signals met the threshold", result.stdout)

    @patch("chimera_intel.core.weak_signal_analyzer.resolve_target")
    @patch("chimera_intel.core.weak_signal_analyzer.get_aggregated_data_for_target")
    def test_cli_wsa_run_no_data(self, mock_get_data, mock_resolve):
        """Tests the CLI command when there is no historical data."""
        mock_resolve.return_value = "example.com"
        mock_get_data.return_value = None

        result = runner.invoke(wsa_app, ["run"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("No historical data", result.stdout)

    @patch("chimera_intel.core.weak_signal_analyzer.resolve_target")
    @patch("chimera_intel.core.weak_signal_analyzer.get_aggregated_data_for_target")
    @patch(
        "chimera_intel.core.weak_signal_analyzer.amplify_signals_with_dempster_shafer"
    )
    def test_cli_wsa_run_with_output_file(
        self, mock_amplify, mock_get_data, mock_resolve
    ):
        """Tests the CLI command with the --output option."""
        mock_resolve.return_value = "example.com"
        mock_get_data.return_value = {"modules": {}}
        mock_amplify.return_value = [
            AmplifiedEventResult(
                event_hypothesis="Test",
                combined_belief=0.8,
                contributing_signals=[],
                summary="Test summary",
            )
        ]

        with patch(
            "chimera_intel.core.weak_signal_analyzer.save_or_print_results"
        ) as mock_save:
            runner.invoke(wsa_app, ["run", "--output", "test.json"])
            mock_save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
