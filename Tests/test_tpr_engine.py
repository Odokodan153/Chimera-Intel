import unittest
import asyncio
from unittest.mock import patch
from typer.testing import CliRunner
from chimera_intel.core.tpr_engine import run_full_tpr_scan, tpr_app
from chimera_intel.core.schemas import (
    TPRMReport,
    VulnerabilityScanResult,
    HIBPResult,
    SWOTAnalysisResult,
    ProjectConfig,
)

runner = CliRunner(mix_stderr=False)


class TestTprEngine(unittest.TestCase):
    """Test cases for the TPRM engine module."""

    @patch("chimera_intel.core.tpr_engine.API_KEYS")
    @patch("chimera_intel.core.tpr_engine.generate_swot_from_data")
    @patch("chimera_intel.core.tpr_engine.check_hibp_breaches")
    @patch("chimera_intel.core.tpr_engine.run_vulnerability_scan")
    def test_run_full_tpr_scan_success(
        self, mock_vuln_scan, mock_breach_check, mock_ai_summary, mock_api_keys
    ):
        """Tests the full TPRM scan orchestration logic with all keys present."""
        mock_vuln_scan.return_value = VulnerabilityScanResult(
            target_domain="vendor.com", scanned_hosts=[]
        )
        mock_breach_check.return_value = HIBPResult(
            breaches=[], message="No breaches found"
        )
        mock_ai_summary.return_value = SWOTAnalysisResult(
            analysis_text="Risk Level: LOW. No significant issues found."
        )
        mock_api_keys.hibp_api_key = "fake_hibp_key"
        mock_api_keys.google_api_key = "fake_google_key"

        result = asyncio.run(run_full_tpr_scan("vendor.com"))

        self.assertIsInstance(result, TPRMReport)
        mock_vuln_scan.assert_called_once_with("vendor.com")
        mock_breach_check.assert_called_once_with("vendor.com", "fake_hibp_key")
        mock_ai_summary.assert_called_once()
        self.assertIn("Risk Level: LOW", result.ai_summary)
        self.assertEqual(result.vulnerability_scan_results.target_domain, "vendor.com")
        self.assertEqual(result.breach_results.message, "No breaches found")

    @patch("chimera_intel.core.tpr_engine.API_KEYS")
    @patch("chimera_intel.core.tpr_engine.run_vulnerability_scan")
    def test_run_tpr_scan_no_hibp_key(self, mock_vuln_scan, mock_api_keys):
        """Tests the TPRM scan when the HIBP API key is missing."""
        mock_vuln_scan.return_value = VulnerabilityScanResult(
            target_domain="vendor.com", scanned_hosts=[]
        )
        mock_api_keys.hibp_api_key = None
        mock_api_keys.google_api_key = None  # Also test no AI key

        result = asyncio.run(run_full_tpr_scan("vendor.com"))

        self.assertIsInstance(result, TPRMReport)
        mock_vuln_scan.assert_called_once_with("vendor.com")
        self.assertIn("HIBP API key not configured", result.breach_results.error)
        self.assertIn("AI analysis skipped", result.ai_summary)

    @patch("chimera_intel.core.tpr_engine.API_KEYS")
    @patch("chimera_intel.core.tpr_engine.generate_swot_from_data")
    @patch("chimera_intel.core.tpr_engine.check_hibp_breaches")
    @patch("chimera_intel.core.tpr_engine.run_vulnerability_scan")
    def test_run_tpr_scan_no_google_key(
        self, mock_vuln_scan, mock_breach_check, mock_ai_summary, mock_api_keys
    ):
        """Tests the TPRM scan when only the Google API key is missing."""
        # Arrange

        mock_vuln_scan.return_value = VulnerabilityScanResult(
            target_domain="vendor.com", scanned_hosts=[]
        )
        mock_breach_check.return_value = HIBPResult(breaches=[])
        mock_api_keys.hibp_api_key = "fake_hibp_key"
        mock_api_keys.google_api_key = None  # Simulate missing Google key

        # Act

        result = asyncio.run(run_full_tpr_scan("vendor.com"))

        # Assert

        self.assertIsInstance(result, TPRMReport)
        self.assertIsNotNone(result.vulnerability_scan_results)
        self.assertIsNotNone(result.breach_results)
        # Ensure the AI summary reflects the skipped analysis

        self.assertIn("AI analysis skipped", result.ai_summary)
        # Ensure the AI function was NOT called

        mock_ai_summary.assert_not_called()

    @patch("chimera_intel.core.tpr_engine.API_KEYS")
    @patch("chimera_intel.core.tpr_engine.generate_swot_from_data")
    @patch("chimera_intel.core.tpr_engine.check_hibp_breaches")
    @patch("chimera_intel.core.tpr_engine.run_vulnerability_scan")
    def test_run_full_tpr_scan_vuln_scan_fails(
        self, mock_vuln_scan, mock_breach_check, mock_ai_summary, mock_api_keys
    ):
        """Tests the TPRM scan's resilience when the vulnerability scan fails."""
        # Arrange: Simulate a failure in the vulnerability scan

        mock_vuln_scan.return_value = VulnerabilityScanResult(
            target_domain="vendor.com",
            scanned_hosts=[],
            error="Nmap scan failed unexpectedly.",
        )
        # Other scans succeed

        mock_breach_check.return_value = HIBPResult(breaches=[])
        mock_ai_summary.return_value = SWOTAnalysisResult(
            analysis_text="Risk Level: MEDIUM"
        )
        mock_api_keys.hibp_api_key = "fake_hibp_key"
        mock_api_keys.google_api_key = "fake_google_key"

        # Act

        result = asyncio.run(run_full_tpr_scan("vendor.com"))

        # Assert

        self.assertIsInstance(result, TPRMReport)
        # Check that the error from the vulnerability scan is correctly reported

        self.assertIsNotNone(result.vulnerability_scan_results.error)
        self.assertIn("Nmap scan failed", result.vulnerability_scan_results.error)
        # Ensure that the breach check results are still present

        self.assertIsNotNone(result.breach_results)
        # Ensure the AI summary was still generated based on the partial data

        self.assertIn("Risk Level: MEDIUM", result.ai_summary)

    @patch("chimera_intel.core.tpr_engine.API_KEYS")
    @patch("chimera_intel.core.tpr_engine.generate_swot_from_data")
    @patch("chimera_intel.core.tpr_engine.check_hibp_breaches")
    @patch("chimera_intel.core.tpr_engine.run_vulnerability_scan")
    def test_run_full_tpr_scan_breach_check_fails(
        self, mock_vuln_scan, mock_breach_check, mock_ai_summary, mock_api_keys
    ):
        """Tests the TPRM scan's resilience when the breach check fails."""
        # Arrange: Simulate a failure in the HIBP breach check

        mock_vuln_scan.return_value = VulnerabilityScanResult(
            target_domain="vendor.com", scanned_hosts=[]
        )
        mock_breach_check.return_value = HIBPResult(
            error="HIBP API call failed due to timeout."
        )
        mock_ai_summary.return_value = SWOTAnalysisResult(
            analysis_text="Risk Level: UNKNOWN"
        )
        mock_api_keys.hibp_api_key = "fake_hibp_key"
        mock_api_keys.google_api_key = "fake_google_key"

        # Act

        result = asyncio.run(run_full_tpr_scan("vendor.com"))

        # Assert

        self.assertIsInstance(result, TPRMReport)
        # Ensure the vulnerability scan results are present

        self.assertIsNotNone(result.vulnerability_scan_results)
        # Check that the error from the breach check is correctly reported

        self.assertIsNotNone(result.breach_results.error)
        self.assertIn("HIBP API call failed", result.breach_results.error)
        # Ensure the AI summary was still generated based on the partial data

        self.assertIn("Risk Level: UNKNOWN", result.ai_summary)

    # --- NEW: Project-Aware CLI Tests ---

    @patch("chimera_intel.core.project_manager.get_active_project")
    @patch("chimera_intel.core.tpr_engine.run_full_tpr_scan")
    def test_cli_tpr_run_with_project(self, mock_run_scan, mock_get_active_project):
        """Tests the CLI command using an active project's domain."""
        # Arrange

        mock_get_active_project.return_value = ProjectConfig(
            project_name="test-project", created_at="", domain="project-tpr.com"
        )

        # Mock the async function's Pydantic result model

        mock_run_scan.return_value = TPRMReport(
            target_domain="project-tpr.com",
            ai_summary="All clear.",
            vulnerability_scan_results=VulnerabilityScanResult(
                target_domain="project-tpr.com", scanned_hosts=[]
            ),
            breach_results=HIBPResult(breaches=[]),
        )

        # Act: Corrected the command path

        result = runner.invoke(tpr_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Using domain 'project-tpr.com' from active project", result.stdout
        )
        mock_run_scan.assert_called_with("project-tpr.com")

    @patch("chimera_intel.core.project_manager.get_active_project")
    def test_cli_tpr_run_no_domain_no_project(self, mock_get_project):
        """Tests CLI failure when no domain is provided and no project is active."""
        # Arrange

        mock_get_project.return_value = None

        # Act

        with patch(
            "chimera_intel.core.tpr_engine.resolve_target"
        ) as mock_resolve_target:
            mock_resolve_target.side_effect = SystemExit(1)
            result = runner.invoke(tpr_app, [])
        # Assert

        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
