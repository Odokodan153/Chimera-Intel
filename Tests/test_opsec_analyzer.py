import unittest
import json
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.opsec_analyzer import generate_opsec_report, opsec_app
from chimera_intel.core.schemas import OpsecReport, CompromisedCommitter

runner = CliRunner()


class TestOpsecAnalyzer(unittest.TestCase):
    """Test cases for the Operational Security (OPSEC) Analysis module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.opsec_analyzer.get_aggregated_data_for_target")
    def test_generate_opsec_report_compromised_committer_found(self, mock_get_agg_data):
        """Tests the detection of a compromised committer."""
        # Arrange

        mock_get_agg_data.return_value = {
            "target": "example.com",
            "modules": {
                "code_intel_repo": {
                    "repository_url": "http://github.com/example/repo",
                    "top_committers": [
                        {"email": "dev@example.com"},
                        {"email": "admin@example.com"},
                    ],
                },
                "defensive_breaches": {
                    "breaches": [
                        {"Name": "Breach1", "DataClasses": ["dev@example.com"]}
                    ]
                },
            },
        }

        # Act

        result = generate_opsec_report("example.com")

        # Assert

        self.assertIsInstance(result, OpsecReport)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.compromised_committers), 1)
        self.assertEqual(result.compromised_committers[0].email, "dev@example.com")
        self.assertIn("Breach1", result.compromised_committers[0].related_breaches)

    @patch("chimera_intel.core.opsec_analyzer.get_aggregated_data_for_target")
    def test_generate_opsec_report_no_findings(self, mock_get_agg_data):
        """Tests the report generation when no OPSEC issues are found."""
        # Arrange

        mock_get_agg_data.return_value = {
            "target": "example.com",
            "modules": {
                "code_intel_repo": {"top_committers": [{"email": "safe@example.com"}]},
                "defensive_breaches": {"breaches": []},
            },
        }

        # Act

        result = generate_opsec_report("example.com")

        # Assert

        self.assertEqual(len(result.compromised_committers), 0)
        self.assertIsNone(result.error)

    def test_generate_opsec_report_no_data(self):
        """Tests report generation when no historical data is available."""
        with patch(
            "chimera_intel.core.opsec_analyzer.get_aggregated_data_for_target",
            return_value=None,
        ):
            result = generate_opsec_report("example.com")
            self.assertIsNotNone(result.error)
            self.assertIn("No historical data found", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.opsec_analyzer.resolve_target")
    @patch("chimera_intel.core.opsec_analyzer.generate_opsec_report")
    def test_cli_opsec_run_success(self, mock_generate, mock_resolve):
        """Tests a successful run of the 'opsec run' CLI command."""
        # Arrange

        mock_resolve.return_value = "example.com"
        mock_generate.return_value = OpsecReport(
            target="example.com",
            compromised_committers=[
                CompromisedCommitter(email="test@example.com", related_breaches=[])
            ],
        )

        # Act

        result = runner.invoke(opsec_app, ["run", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_generate.assert_called_with("example.com")
        output = json.loads(result.stdout)
        self.assertEqual(len(output["compromised_committers"]), 1)
        self.assertEqual(
            output["compromised_committers"][0]["email"], "test@example.com"
        )

    @patch("chimera_intel.core.opsec_analyzer.resolve_target")
    @patch("chimera_intel.core.opsec_analyzer.generate_opsec_report")
    def test_cli_opsec_run_with_project(self, mock_generate, mock_resolve):
        """Tests the CLI command using an active project's context."""
        # Arrange

        mock_resolve.return_value = "project.com"
        mock_generate.return_value = OpsecReport(target="project.com")

        # Act

        result = runner.invoke(opsec_app, ["run"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_resolve.assert_called_with(
            None, required_assets=["company_name", "domain"]
        )
        mock_generate.assert_called_with("project.com")


if __name__ == "__main__":
    unittest.main()
