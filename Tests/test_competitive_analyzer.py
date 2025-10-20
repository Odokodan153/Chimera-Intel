import unittest
from unittest.mock import patch
from typer.testing import CliRunner
import typer

# Import the module itself to patch its objects
from chimera_intel.core import competitive_analyzer
from chimera_intel.core.competitive_analyzer import (
    generate_competitive_analysis,
    competitive_analyzer_app,
)
from chimera_intel.core.schemas import CompetitiveAnalysisResult, SWOTAnalysisResult

runner = CliRunner()


class TestCompetitiveAnalyzer(unittest.TestCase):
    """Test cases for the Competitive Analyzer module."""

    @patch("chimera_intel.core.competitive_analyzer.generate_swot_from_data")
    def test_generate_competitive_analysis_success(self, mock_ai_generate):
        """Tests a successful competitive analysis generation."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="## Competitive Analysis"
        )
        target_a_data = {"target": "Company A", "modules": {}}
        target_b_data = {"target": "Company B", "modules": {}}

        # Act

        result = generate_competitive_analysis(
            target_a_data, target_b_data, "fake_google_key"
        )

        # Assert

        self.assertIsInstance(result, CompetitiveAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.analysis_text, "## Competitive Analysis")
        mock_ai_generate.assert_called_once()

    def test_generate_competitive_analysis_no_api_key(self):
        """Tests that the function returns an error if no API key is provided."""
        # Act

        result = generate_competitive_analysis({}, {}, "")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("GOOGLE_API_KEY not found", result.error)

    @patch("chimera_intel.core.competitive_analyzer.generate_swot_from_data")
    def test_generate_competitive_analysis_api_error(self, mock_ai_generate):
        """Tests error handling when the AI generation function fails."""
        # Arrange

        mock_ai_generate.return_value = SWOTAnalysisResult(
            analysis_text="", error="API error"
        )

        # Act

        result = generate_competitive_analysis({}, {}, "fake_google_key")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("An error occurred with the Google AI API", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.competitive_analyzer.resolve_target")
    @patch("chimera_intel.core.competitive_analyzer.console.print")
    @patch("chimera_intel.core.competitive_analyzer.get_aggregated_data_for_target")
    @patch("chimera_intel.core.competitive_analyzer.generate_competitive_analysis")
    def test_cli_competitive_analysis_success(
        self, mock_generate, mock_get_data, mock_console, mock_resolve
    ):
        """Tests the 'competitive' CLI command with a successful run."""
        # Arrange
        
        # FIX: Mock resolve_target to return the targets
        mock_resolve.side_effect = ["companyA", "companyB"]

        mock_get_data.side_effect = [
            {"target": "companyA", "modules": {}},
            {"target": "companyB", "modules": {}},
        ]
        mock_generate.return_value = CompetitiveAnalysisResult(
            analysis_text="**Test Analysis**"
        )
    
        with patch.object(competitive_analyzer.API_KEYS, "google_api_key", "fake_key"):
            # Act
            result = runner.invoke(
                competitive_analyzer_app, ["run", "companyA", "companyB"]
            )
    
        # Assert
        self.assertEqual(result.exit_code, 0) # This should now pass

    @patch("chimera_intel.core.competitive_analyzer.resolve_target")
    @patch("chimera_intel.core.competitive_analyzer.console.print")
    @patch("chimera_intel.core.competitive_analyzer.get_aggregated_data_for_target")
    def test_cli_competitive_analysis_no_data(self, mock_get_data, mock_console, mock_resolve):
        """Tests the CLI command when data for one of the targets is missing."""
        # Arrange
        
        # FIX: Mock resolve_target to return the targets
        mock_resolve.side_effect = ["companyA", "companyB"]
        
        mock_get_data.side_effect = [
            {"target": "companyA", "modules": {}},  # First call (companyA) succeeds
            None,  # Second call (companyB) fails
        ]
    
        with patch.object(competitive_analyzer.API_KEYS, "google_api_key", "fake_key"):
            # Act
            result = runner.invoke(
                competitive_analyzer_app, ["run", "companyA", "companyB"]
            )
    
        # Assert
        exit_code = result.exit_code
        if isinstance(result.exception, typer.Exit):
            exit_code = result.exception.exit_code
    
        self.assertEqual(exit_code, 1) # This should now pass

    @patch("chimera_intel.core.competitive_analyzer.resolve_target")
    @patch("chimera_intel.core.competitive_analyzer.console.print")
    @patch("chimera_intel.core.competitive_analyzer.get_aggregated_data_for_target")
    def test_cli_competitive_analysis_no_api_key(self, mock_get_data, mock_console, mock_resolve):
        """NEW: Tests the CLI command when the Google API key is not configured."""
        # Arrange
        
        # FIX: Mock resolve_target to return the targets
        mock_resolve.side_effect = ["companyA", "companyB"]
        
        mock_get_data.return_value = {"target": "companyA", "modules": {}}
    
        with patch.object(competitive_analyzer.API_KEYS, "google_api_key", None):
            # Act
            result = runner.invoke(
                competitive_analyzer_app, ["run", "companyA", "companyB"]
            )
    
        # Assert
        exit_code = result.exit_code
        if isinstance(result.exception, typer.Exit):
            exit_code = result.exception.exit_code
    
        self.assertEqual(exit_code, 1) # This should now pass


if __name__ == "__main__":
    unittest.main()