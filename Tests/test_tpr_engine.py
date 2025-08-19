import unittest
import asyncio
from unittest.mock import patch
from chimera_intel.core.tpr_engine import run_full_tpr_scan
from chimera_intel.core.schemas import (
    TPRMReport,
    VulnerabilityScanResult,
    HIBPResult,
    SWOTAnalysisResult
)

class TestTprEngine(unittest.TestCase):
    """Test cases for the TPRM engine module."""

    @patch("chimera_intel.core.tpr_engine.API_KEYS")
    @patch("chimera_intel.core.tpr_engine.generate_swot_from_data")
    @patch("chimera_intel.core.tpr_engine.check_hibp_breaches")
    @patch("chimera_intel.core.tpr_engine.run_vulnerability_scan")
    def test_run_full_tpr_scan(
        self,
        mock_vuln_scan,
        mock_breach_check,
        mock_ai_summary,
        mock_api_keys
    ):
        """Tests the full TPRM scan orchestration logic."""
        # --- 1. Setup Mocks ---
        # Mock the return values of the individual scanners
        mock_vuln_scan.return_value = VulnerabilityScanResult(
            target_domain="vendor.com",
            scanned_hosts=[] # Keep it simple for this test
        )
        mock_breach_check.return_value = HIBPResult(
            breaches=[],
            message="No breaches found"
        )
        # Mock the AI summary generation
        mock_ai_summary.return_value = SWOTAnalysisResult(
            analysis_text="Risk Level: LOW. No significant issues found."
        )
        # Mock the API keys
        mock_api_keys.hibp_api_key = "fake_hibp_key"
        mock_api_keys.google_api_key = "fake_google_key"

        # --- 2. Run the Asynchronous Function ---
        # We need to create an event loop to run the async function in a sync test
        result = asyncio.run(run_full_tpr_scan("vendor.com"))

        # --- 3. Assertions ---
        # Verify that the orchestrator returns the correct aggregated model
        self.assertIsInstance(result, TPRMReport)
        
        # Verify that the underlying scanners were called
        mock_vuln_scan.assert_called_once_with("vendor.com")
        mock_breach_check.assert_called_once_with("vendor.com", "fake_hibp_key")
        
        # Verify that the AI summary was generated
        mock_ai_summary.assert_called_once()
        self.assertIn("Risk Level: LOW", result.ai_summary)
        
        # Verify that the data from the scanners is present in the final report
        self.assertEqual(result.vulnerability_scan_results.target_domain, "vendor.com")
        self.assertEqual(result.breach_results.message, "No breaches found")

if __name__ == "__main__":
    unittest.main()