import unittest
from unittest.mock import patch

from chimera_intel.core.opsec_analyzer import generate_opsec_report
from chimera_intel.core.schemas import OpsecReport


class TestOpsecAnalyzer(unittest.TestCase):
    """Test cases for the Operational Security (OPSEC) Analysis module."""

    @patch("chimera_intel.core.opsec_analyzer.get_aggregated_data_for_target")
    def test_generate_opsec_report_finds_compromised_committer(self, mock_get_agg_data):
        """Tests that the correlation logic correctly identifies a compromised committer."""
        # Arrange: Mock database data showing a committer email also present in a breach

        mock_get_agg_data.return_value = {
            "modules": {
                "code_intel_repo": {
                    "repository_url": "https://github.com/test/repo.git",
                    "top_committers": [{"email": "developer@example.com"}],
                },
                "defensive_breaches": {
                    "breaches": [
                        {
                            "Name": "BigBreach2025",
                            "DataClasses": ["Email addresses", "developer@example.com"],
                        }
                    ]
                },
            }
        }

        # Act

        result = generate_opsec_report("example.com")

        # Assert

        self.assertIsInstance(result, OpsecReport)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.compromised_committers), 1)
        self.assertEqual(
            result.compromised_committers[0].email, "developer@example.com"
        )

    @patch("chimera_intel.core.opsec_analyzer.get_aggregated_data_for_target")
    def test_generate_opsec_report_no_correlation(self, mock_get_agg_data):
        """Tests that no compromised committers are flagged if there is no correlation."""
        # Arrange

        mock_get_agg_data.return_value = {
            "modules": {
                "code_intel_repo": {
                    "top_committers": [{"email": "safe.dev@example.com"}]
                },
                "defensive_breaches": {"breaches": [{"Name": "BigBreach2025"}]},
            }
        }

        # Act

        result = generate_opsec_report("example.com")

        # Assert

        self.assertEqual(len(result.compromised_committers), 0)


if __name__ == "__main__":
    unittest.main()
