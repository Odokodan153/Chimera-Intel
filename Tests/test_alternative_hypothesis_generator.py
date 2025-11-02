import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.alternative_hypothesis_generator import (
    generate_alternative_hypotheses,
    alternative_hypothesis_app,
)
from chimera_intel.core.schemas import AlternativeHypothesisResult, SWOTAnalysisResult

runner = CliRunner()


class TestAlternativeHypothesisGenerator(unittest.TestCase):

    @patch("chimera_intel.core.alternative_hypothesis_generator.get_aggregated_data_for_target")
    @patch("chimera_intel.core.alternative_hypothesis_generator.generate_swot_from_data")
    @patch("chimera_intel.core.alternative_hypothesis_generator.API_KEYS")
    def test_generate_alternative_hypotheses_success(
        self, mock_api_keys, mock_ai_call, mock_get_data
    ):
        """Tests successful alternative hypothesis generation."""
        # Arrange
        mock_api_keys.google_api_key = "fake_key"
        mock_get_data.return_value = {
            "modules": {
                "vulnerability_scan": {
                    "vulnerabilities": [{"id": "CVE-2024-1234", "severity": "CRITICAL"}]
                }
            }
        }
        mock_ai_call.return_value = SWOTAnalysisResult(
            analysis_text="Alt: The vulnerability is a honeypot.", error=None
        )

        # Act
        result = generate_alternative_hypotheses("example.com")

        # Assert
        self.assertIsInstance(result, AlternativeHypothesisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.target, "example.com")
        self.assertIn("Target has 1 critical vulnerabilities", result.primary_findings_summary)
        self.assertIn("Alt: The vulnerability is a honeypot", result.ai_raw_analysis)
        mock_ai_call.assert_called_once()

    @patch("chimera_intel.core.alternative_hypothesis_generator.get_aggregated_data_for_target")
    def test_generate_alt_hyp_no_primary_findings(self, mock_get_data):
        """Tests when no primary findings are available to challenge."""
        # Arrange
        mock_get_data.return_value = {
            "modules": {} # No modules with findings
        }

        # Act
        result = generate_alternative_hypotheses("example.com")

        # Assert
        self.assertIsInstance(result, AlternativeHypothesisResult)
        self.assertIsNotNone(result.error)
        self.assertIn("No primary findings found", result.error)

    @patch("chimera_intel.core.alternative_hypothesis_generator.get_aggregated_data_for_target")
    def test_generate_alt_hyp_no_data(self, mock_get_data):
        """Tests when no aggregated data is found for the target."""
        # Arrange
        mock_get_data.return_value = None

        # Act
        result = generate_alternative_hypotheses("example.com")

        # Assert
        self.assertIsInstance(result, AlternativeHypothesisResult)
        self.assertIsNotNone(result.error)
        self.assertIn("No historical data found", result.error)

    @patch("chimera_intel.core.alternative_hypothesis_generator.resolve_target")
    @patch("chimera_intel.core.alternative_hypothesis_generator.generate_alternative_hypotheses")
    @patch("chimera_intel.core.alternative_hypothesis_generator.save_or_print_results")
    @patch("chimera_intel.core.alternative_hypothesis_generator.save_scan_to_db")
    def test_cli_alternative_hypothesis_run(
        self, mock_save_db, mock_save_print, mock_generate, mock_resolve
    ):
        """Tests the 'run' CLI command for alternative-hypothesis."""
        # Arrange
        mock_resolve.return_value = "example.com"
        mock_dump_dict = {"target": "example.com"}
        mock_result = MagicMock(model_dump=lambda exclude_none: mock_dump_dict)
        mock_generate.return_value = mock_result

        # Act
        result = runner.invoke(alternative_hypothesis_app, ["run", "example.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        mock_resolve.assert_called_with("example.com")
        mock_generate.assert_called_with("example.com")
        mock_save_print.assert_called_with(mock_dump_dict, None)
        mock_save_db.assert_called_with(
            target="example.com", module="alternative_hypothesis", data=mock_dump_dict
        )