import unittest
from unittest.mock import patch, mock_open
from chimera_intel.core.automation import (
    enrich_iocs,
    generate_threat_model,
    analyze_behavioral_logs,
    enrich_cves,
    submit_to_virustotal,
    run_workflow,
)


class TestAutomation(unittest.TestCase):
    """Test cases for the analysis and automation module."""

    def test_enrich_iocs(self):
        """Tests the IOC enrichment function."""
        result = enrich_iocs(["8.8.8.8", "example.com"])
        self.assertIsNotNone(result)
        self.assertEqual(result.total_enriched, 2)
        self.assertTrue(result.enriched_iocs[0].is_malicious)

    def test_generate_threat_model(self):
        """Tests the threat model generation function."""
        result = generate_threat_model("example.com")
        self.assertIsNotNone(result)
        self.assertEqual(len(result.potential_paths), 1)
        self.assertEqual(result.potential_paths[0].confidence, "High")

    def test_analyze_behavioral_logs(self):
        """Tests the UEBA log analysis function."""
        result = analyze_behavioral_logs("ad_logon.csv")
        self.assertIsNotNone(result)
        self.assertEqual(result.total_anomalies_found, 1)
        self.assertEqual(result.anomalies[0].severity, "Critical")

    def test_enrich_cves(self):
        """Tests the CVE enrichment function."""
        result = enrich_cves(["CVE-2021-44228"])
        self.assertIsNotNone(result)
        self.assertEqual(result.total_enriched, 1)
        self.assertEqual(result.enriched_cves[0].cve_id, "CVE-2021-44228")

    @patch("chimera_intel.core.automation.API_KEYS.virustotal_api_key", "fake_key")
    def test_submit_to_virustotal(self):
        """Tests the VirusTotal submission function."""
        result = submit_to_virustotal("malicious.exe")
        self.assertIsNotNone(result)
        self.assertEqual(result.response_code, 1)
        self.assertIn("virustotal.com", result.permalink)

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="target: example.com\\nsteps:\\n  - run: scan footprint {target}",
    )
    def test_run_workflow(self, mock_file):
        """Tests the workflow execution function."""
        # This test ensures the function runs and correctly parses the mock file.
        # A more advanced test could patch subprocess to verify the commands.

        run_workflow("workflow.yaml")
        mock_file.assert_called_once_with("workflow.yaml", "r")


if __name__ == "__main__":
    unittest.main()
