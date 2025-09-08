import unittest
from unittest.mock import patch, MagicMock, mock_open, AsyncMock
from chimera_intel.core.automation import (
    enrich_iocs,
    generate_threat_model,
    analyze_behavioral_logs,
    enrich_cves,
    submit_to_virustotal,
    run_workflow,
)
from chimera_intel.core.schemas import (
    ThreatIntelResult,
    AttackPath,
    BehavioralAnomaly,
    VTSubmissionResult,
)


class TestAutomation(unittest.IsolatedAsyncioTestCase):
    """Test cases for the analysis and automation module."""

    @patch("chimera_intel.core.automation.API_KEYS.otx_api_key", "fake_key")
    @patch("chimera_intel.core.automation.get_threat_intel_otx", new_callable=AsyncMock)
    async def test_enrich_iocs(self, mock_get_intel):
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
        self.assertEqual(mock_get_intel.call_count, 2)

    @patch("chimera_intel.core.automation.sync_client.post")
    def test_enrich_cves(self, mock_post):
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

            # Act

            result = enrich_cves(["CVE-2021-44228"])

            # Assert

            self.assertIsNotNone(result)
            self.assertEqual(result.total_enriched, 1)
            self.assertEqual(result.enriched_cves[0].cve_id, "CVE-2021-44228")
            self.assertEqual(result.enriched_cves[0].cvss_score, 10.0)

    @patch("chimera_intel.core.automation.get_aggregated_data_for_target")
    def test_generate_threat_model(self, mock_get_data):
        """Tests the threat model generation by providing mock historical data."""
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

        # Act

        result = generate_threat_model("example.com")

        # Assert

        self.assertIsNotNone(result)
        self.assertEqual(len(result.potential_paths), 1)
        self.assertIsInstance(result.potential_paths[0], AttackPath)
        self.assertIn("Exploit CVE-2023-1234", result.potential_paths[0].path[0])

    def test_analyze_behavioral_logs(self):
        """Tests the UEBA log analysis function with a mocked log file."""
        # Baseline logs

        baseline_logs = (
            "timestamp,user,source_ip,action\n"
            "2025-09-08T10:00:00Z,user1,192.168.1.10,login_success\n"
            "2025-09-08T11:00:00Z,user1,192.168.1.10,read_file\n"
        )
        # Logs containing anomalies

        anomaly_logs = (
            "timestamp,user,source_ip,action\n"
            "2025-09-08T03:00:00Z,user1,10.0.0.5,login_success\n"
            "2025-09-08T12:00:00Z,user1,192.168.1.10,login_success\n"
        )
        # Combine baseline and anomaly logs for the test

        combined_logs = baseline_logs + anomaly_logs.split("\n", 1)[1]

        with patch("builtins.open", mock_open(read_data=combined_logs)):
            with patch("os.path.exists", return_value=True):
                result = analyze_behavioral_logs("/fake/path/logs.csv")

                self.assertIsNotNone(result)
                self.assertEqual(result.total_anomalies_found, 2)
                self.assertIsInstance(result.anomalies[0], BehavioralAnomaly)
                self.assertIn("new source IP", result.anomalies[0].anomaly_description)
                self.assertIn("unusual time", result.anomalies[1].anomaly_description)

    @patch("chimera_intel.core.automation.os.path.exists", return_value=True)
    @patch("chimera_intel.core.automation.sync_client")
    def test_submit_to_virustotal(self, mock_client, mock_exists):
        """Tests the VirusTotal submission function by mocking the HTTP client."""
        with patch(
            "chimera_intel.core.automation.API_KEYS.virustotal_api_key", "fake_key"
        ):
            mock_get_response = MagicMock()
            mock_get_response.raise_for_status.return_value = None
            mock_get_response.json.return_value = {"data": "http://upload.url"}

            mock_post_response = MagicMock()
            mock_post_response.raise_for_status.return_value = None
            # Use an ID without "-" to match resource_id parsing

            mock_post_response.json.return_value = {"data": {"id": "sha256offile12345"}}

            mock_client.get.return_value = mock_get_response
            mock_client.post.return_value = mock_post_response

            with patch("builtins.open", mock_open(read_data=b"malware")):
                result = submit_to_virustotal("malicious.exe")

                self.assertIsInstance(result, VTSubmissionResult)
                self.assertEqual(result.response_code, 1)
                self.assertIn("sha256offile12345", result.permalink)
                self.assertIsNone(result.error)

    @patch("chimera_intel.core.automation.subprocess.run")
    def test_run_workflow(self, mock_subprocess_run):
        """Tests the workflow execution function by mocking the subprocess call."""
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
            self.assertIn("chimera scan footprint example.com", first_call_args)


if __name__ == "__main__":
    unittest.main()
