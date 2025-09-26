import unittest

from chimera_intel.core.weak_signal_analyzer import (
    generate_weak_signals,
    amplify_signals_with_dempster_shafer,
)
from chimera_intel.core.schemas import WeakSignal


class TestWSA(unittest.TestCase):
    """Test cases for the Weak Signal Amplification module."""

    def test_generate_weak_signals(self):
        """Tests that weak signals are correctly generated from mock data."""
        aggregated_data = {
            "modules": {
                "business_intel": {
                    "news": {"totalArticles": 25},
                    "financials": {"trailingPE": 10},
                }
            }
        }
        signals = generate_weak_signals(aggregated_data)
        self.assertEqual(len(signals), 2)
        self.assertTrue(any(s.signal_type == "MergerOrAcquisition" for s in signals))

    def test_generate_weak_signals_no_signals(self):
        """Tests that no signals are generated when no rules are met."""
        aggregated_data = {
            "modules": {
                "business_intel": {
                    "news": {"totalArticles": 5},
                    "financials": {"trailingPE": 30},
                }
            }
        }
        signals = generate_weak_signals(aggregated_data)
        self.assertEqual(len(signals), 0)

    def test_dempster_shafer_combination(self):
        """Tests the mathematical correctness of the Dempster-Shafer combination rule."""
        signals = [
            WeakSignal(source_module="A", signal_type="X", description="", belief=0.3),
            WeakSignal(source_module="B", signal_type="X", description="", belief=0.4),
        ]
        results = amplify_signals_with_dempster_shafer(signals)
        self.assertAlmostEqual(results[0].combined_belief, 0.58)

    def test_amplification_with_insufficient_signals(self):
        """Tests that amplification is not performed if only one signal is present."""
        signals = [
            WeakSignal(source_module="A", signal_type="X", description="", belief=0.3)
        ]
        results = amplify_signals_with_dempster_shafer(signals)
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
