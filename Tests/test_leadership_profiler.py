import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.leadership_profiler import (
    profile_leadership,
    leadership_profiler_app,
)
from chimera_intel.core.schemas import LeadershipProfileResult, GoogleSearchResults, SWOTAnalysisResult

runner = CliRunner()


class TestLeadershipProfiler(unittest.TestCase):

    @patch("chimera_intel.core.leadership_profiler.run_google_search")
    @patch("chimera_intel.core.leadership_profiler.generate_swot_from_data")
    @patch("chimera_intel.core.leadership_profiler.API_KEYS")
    def test_profile_leadership_success(
        self, mock_api_keys, mock_ai_call, mock_google_search
    ):
        """Tests successful leadership profiling."""
        # Arrange
        mock_api_keys.google_api_key = "fake_key"
        mock_google_search.return_value = GoogleSearchResults(
            results=[
                {"url": "test.com", "snippet": "John Doe donated $1M to Party X."}
            ],
            total_results=1,
            error=None
        )
        mock_ai_call.return_value = SWOTAnalysisResult(
            analysis_text="Finding: Strong political affiliation.", error=None
        )

        # Act
        result = profile_leadership("John Doe", "Example Inc")

        # Assert
        self.assertIsInstance(result, LeadershipProfileResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.person_name, "John Doe")
        self.assertEqual(result.company, "Example Inc")
        self.assertIn("Strong political affiliation", result.analysis_summary)
        mock_google_search.assert_called_once()
        mock_ai_call.assert_called_once()

    @patch("chimera_intel.core.leadership_profiler.run_google_search")
    def test_profile_leadership_no_data(self, mock_google_search):
        """Tests leadership profiling when no OSINT data is found."""
        # Arrange
        mock_google_search.return_value = GoogleSearchResults(
            results=[], total_results=0, error=None
        )

        # Act
        result = profile_leadership("Jane Doe", "Example Inc")

        # Assert
        self.assertIsInstance(result, LeadershipProfileResult)
        self.assertIsNotNone(result.error)
        self.assertIn("No public OSINT data found", result.error)

    @patch("chimera_intel.core.leadership_profiler.profile_leadership")
    @patch("chimera_intel.core.leadership_profiler.get_active_project")
    @patch("chimera_intel.core.leadership_profiler.save_or_print_results")
    @patch("chimera_intel.core.leadership_profiler.save_scan_to_db")
    def test_cli_leadership_profiler_run(
        self, mock_save_db, mock_save_print, mock_get_project, mock_profile
    ):
        """Tests the 'run' CLI command for leadership-profiler."""
        # Arrange
        mock_get_project.return_value = MagicMock(company_name="Example Inc")
        mock_dump_dict = {"person_name": "John Doe"}
        mock_result = MagicMock(model_dump=lambda exclude_none: mock_dump_dict)
        mock_profile.return_value = mock_result

        # Act
        result = runner.invoke(leadership_profiler_app, ["run", "--person", "John Doe"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        mock_get_project.assert_called_once()
        mock_profile.assert_called_with("John Doe", "Example Inc")
        mock_save_print.assert_called_with(mock_dump_dict, None)
        mock_save_db.assert_called_with(
            target="John Doe@Example Inc",
            module="corporate_leadership_profile",
            data=mock_dump_dict,
        )

    @patch("chimera_intel.core.leadership_profiler.profile_leadership")
    @patch("chimera_intel.core.leadership_profiler.get_active_project")
    def test_cli_leadership_profiler_no_company(
        self, mock_get_project, mock_profile
    ):
        """Tests CLI failure when no company is provided or found."""
        # Arrange
        mock_get_project.return_value = None  # No active project

        # Act
        result = runner.invoke(leadership_profiler_app, ["run", "--person", "John Doe"])

        # Assert
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("No company name provided", result.stdout)
        mock_profile.assert_not_called()