import unittest
from unittest.mock import patch, MagicMock, mock_open, AsyncMock
import subprocess
from chimera_intel.core.automation import (
    enrich_iocs,
    enrich_cves,
    analyze_behavioral_logs,
    submit_to_virustotal,
    generate_threat_model,
    run_workflow,
)
from chimera_intel.core.schemas import (
    ThreatIntelResult,
    AttackPath,
    VTSubmissionResult,
)


class TestAutomation(unittest.IsolatedAsyncioTestCase):
    """Test cases for the analysis and automation module."""

    @patch("chimera_intel.core.automation.get_threat_intel_otx", new_callable=AsyncMock)
    @patch("chimera_intel.core.automation.API_KEYS.otx_api_key", "fake_key")
    async def test_enrich_iocs_success(self, mock_get_intel):
        """Tests the IOC enrichment function by mocking the OTX intel source."""
        # Arrange

        mock_get_intel.side_effect = [
            ThreatIntelResult(indicator="8.8.8.8", is_malicious=False, pulse_count=0),
            ThreatIntelResult(indicator="1.2.3.4", is_malicious=True, pulse_count=5),
        ]

        # Act

        result = await enrich_iocs(["8.8.8.8", "1.2.3.4"])

        # Assert

        self.assertIsNotNone(result)
        self.assertEqual(result.total_enriched, 2)
        self.assertFalse(result.enriched_iocs[0].is_malicious)
        self.assertTrue(result.enriched_iocs[1].is_malicious)
        self.assertEqual(result.enriched_iocs[1].indicator, "1.2.3.4")

    async def test_enrich_iocs_no_api_key(self):
        """Tests IOC enrichment when the OTX API key is missing."""
        with patch("chimera_intel.core.automation.API_KEYS.otx_api_key", None):
            result = await enrich_iocs(["8.8.8.8"])
            self.assertIsNotNone(result.error)
            self.assertIn("OTX API key not found", result.error)

    @patch("chimera_intel.core.automation.sync_client.post")
    def test_enrich_cves_success(self, mock_post):
        """Tests the CVE enrichment function by mocking the Vulners API call."""
        with patch(
            "chimera_intel.core.automation.API_KEYS.vulners_api_key", "fake_key"
        ):
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = {
                "data": {
                    "documents": {
                        "CVE-2021-44228": {
                            "id": "CVE-2021-44228",
                            "description": "Log4j vulnerability",
                            "cvss": {"score": 10.0},
                            "references": [{"href": "http://example.com"}],
                        }
                    }
                }
            }
            mock_post.return_value = mock_response

            result = enrich_cves(["CVE-2021-44228"])

            self.assertIsNotNone(result)
            self.assertEqual(result.total_enriched, 1)
            self.assertEqual(result.enriched_cves[0].cve_id, "CVE-2021-44228")
            self.assertEqual(result.enriched_cves[0].cvss_score, 10.0)

    def test_enrich_cves_no_api_key(self):
        """Tests CVE enrichment when the Vulners API key is missing."""
        with patch("chimera_intel.core.automation.API_KEYS.vulners_api_key", None):
            result = enrich_cves(["CVE-2021-44228"])
            self.assertIsNotNone(result.error)
            self.assertIn("Vulners API key not found", result.error)

    @patch("chimera_intel.core.automation.get_aggregated_data_for_target")
    def test_generate_threat_model_success(self, mock_get_data):
        """Tests threat model generation with mock data."""
        mock_get_data.return_value = {
            "modules": {
                "vulnerability_scanner": {
                    "scanned_hosts": [
                        {
                            "host": "1.2.3.4",
                            "open_ports": [
                                {
                                    "port": 443,
                                    "product": "nginx",
                                    "vulnerabilities": [
                                        {"id": "CVE-2023-1234", "cvss_score": 9.8}
                                    ],
                                }
                            ],
                        }
                    ]
                }
            }
        }
        result = generate_threat_model("example.com")
        self.assertIsNotNone(result)
        self.assertEqual(len(result.potential_paths), 1)
        self.assertIsInstance(result.potential_paths[0], AttackPath)
        self.assertIn("Exploit CVE-2023-1234", result.potential_paths[0].path[0])

    def test_analyze_behavioral_logs_correctly_separates_baseline(self):
        """
        CORRECTED: Tests UEBA log analysis with a separate baseline and anomaly logs.
        """
        # Baseline logs establish what is "normal"

        baseline_logs = (
            "timestamp,user,source_ip,action\n"
            "2025-09-08T10:00:00Z,user1,192.168.1.10,login_success\n"
            "2025-09-08T11:00:00Z,user1,192.168.1.10,read_file\n"
        )
        # Logs containing anomalies to be tested against the baseline.

        anomaly_logs = (
            "2025-09-09T03:00:00Z,user1,10.0.0.5,login_success\n"  # New IP, unusual hour
            "2025-09-09T10:00:00Z,user1,192.168.1.10,login_success\n"  # Normal login
        )

        # Combine the logs for the test file, with baseline first

        combined_logs = baseline_logs + anomaly_logs

        with patch("builtins.open", mock_open(read_data=combined_logs)):
            with patch("os.path.exists", return_value=True):
                result = analyze_behavioral_logs("/fake/path/logs.csv")

                self.assertIsNotNone(result)
                # The function should now correctly identify anomalies from the second half.

                self.assertEqual(result.total_anomalies_found, 2)
                self.assertIn("new source IP", result.anomalies[0].anomaly_description)
                self.assertIn("unusual time", result.anomalies[1].anomaly_description)

    @patch("chimera_intel.core.automation.os.path.exists", return_value=True)
    @patch("chimera_intel.core.automation.sync_client")
    def test_submit_to_virustotal_success(self, mock_client, mock_exists):
        """CORRECTED: Tests VirusTotal submission with a realistic mock response."""
        with patch(
            "chimera_intel.core.automation.API_KEYS.virustotal_api_key", "fake_key"
        ):
            mock_get_response = MagicMock()
            mock_get_response.raise_for_status.return_value = None
            mock_get_response.json.return_value = {"data": "http://upload.url"}

            mock_post_response = MagicMock()
            mock_post_response.raise_for_status.return_value = None
            # CORRECTED: The analysis ID from VirusTotal is the resource's SHA256 hash
            # followed by a hyphen and a timestamp.

            mock_post_response.json.return_value = {
                "data": {"id": "d8e8fca2dc0f896fd7cb4cb0031ba249-1630454400"}
            }

            mock_client.get.return_value = mock_get_response
            mock_client.post.return_value = mock_post_response

            with patch("builtins.open", mock_open(read_data=b"malware")):
                result = submit_to_virustotal("malicious.exe")

                self.assertIsInstance(result, VTSubmissionResult)
                self.assertEqual(result.response_code, 1)
                # The assertion should now pass as the correct resource ID is extracted.

                self.assertIn("d8e8fca2dc0f896fd7cb4cb0031ba249", result.permalink)
                self.assertIsNone(result.error)

    @patch("chimera_intel.core.automation.subprocess.run")
    def test_run_workflow_success(self, mock_subprocess_run):
        """Tests workflow execution by mocking subprocess."""
        mock_yaml_content = (
            "target: example.com\n"
            "steps:\n"
            "  - run: scan footprint {target}\n"
            "  - run: scan web {target}\n"
        )
        with patch("builtins.open", mock_open(read_data=mock_yaml_content)):
            run_workflow("workflow.yaml")

            self.assertEqual(mock_subprocess_run.call_count, 2)
            first_call_args = mock_subprocess_run.call_args_list[0].args[0]
            second_call_args = mock_subprocess_run.call_args_list[1].args[0]
            self.assertIn("chimera scan footprint example.com", first_call_args)
            self.assertIn("chimera scan web example.com", second_call_args)

    @patch("chimera_intel.core.automation.subprocess.run")
    def test_run_workflow_step_failure(self, mock_subprocess_run):
        """Tests workflow execution with a failing step, ensuring it stops."""
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, "cmd")
        mock_yaml_content = (
            "target: example.com\n"
            "steps:\n"
            "  - run: scan footprint {target}\n"
            "  - run: scan web {target}\n"  # This step should not be reached
        )
        with patch("builtins.open", mock_open(read_data=mock_yaml_content)):
            run_workflow("workflow.yaml")

            # The workflow should stop after the first failing step

            mock_subprocess_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
