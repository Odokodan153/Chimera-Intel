import unittest
import asyncio
from unittest.mock import patch, MagicMock
from chimera_intel.core.tpr_engine import run_full_tpr_scan
from chimera_intel.core.schemas import (
    TPRMReport,
    VulnerabilityScanResult,
    HIBPResult,
    SWOTAnalysisResult,
)


class TestTprEngine(unittest.TestCase):
    """Test cases for the TPRM engine module."""

    # FIX: Correct the patch path to where 'generate_swot_from_data' is used.

    @patch("chimera_intel.core.tpr_engine.API_KEYS")
    @patch("chimera_intel.core.tpr_engine.generate_swot_from_data")
    @patch("chimera_intel.core.tpr_engine.check_hibp_breaches")
    @patch("chimera_intel.core.tpr_engine.run_vulnerability_scan")
    def test_run_full_tpr_scan(
        self, mock_vuln_scan, mock_breach_check, mock_ai_summary, mock_api_keys
    ):
        """Tests the full TPRM scan orchestration logic."""
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

    # ADDED: New test to increase coverage

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


if __name__ == "__main__":
    unittest.main()
