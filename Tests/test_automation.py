import unittest
import subprocess
from unittest.mock import patch, MagicMock, mock_open, AsyncMock
from typer.testing import CliRunner
import yaml  # Import yaml to mock its errors

from chimera_intel.core.automation import (
    enrich_iocs,
    enrich_cves,
    analyze_behavioral_logs,
    submit_to_virustotal,
    generate_threat_model,
    run_workflow,
    automation_app,  # Import the Typer app
    # FIX: Removed connect_app
)
from chimera_intel.core.schemas import (
    ThreatIntelResult,
    AttackPath,
    VTSubmissionResult,
)

# CliRunner for testing Typer apps
runner = CliRunner()


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

    # --- Extended Test ---
    @patch("chimera_intel.core.automation.sync_client.post")
    def test_enrich_cves_api_failure(self, mock_post):
        """
        Tests CVE enrichment when the Vulners API call fails.
        Covers the 'except Exception as e' block.
        """
        with patch(
            "chimera_intel.core.automation.API_KEYS.vulners_api_key", "fake_key"
        ):
            mock_post.side_effect = Exception("API is down")
            result = enrich_cves(["CVE-2021-44228"])
            self.assertIsNotNone(result.error)
            self.assertIn(
                "An error occurred with the Vulners API: API is down", result.error
            )

    @patch("chimera_intel.core.automation.get_aggregated_data_for_target")
    def test_generate_threat_model_success_rule_1_vuln(self, mock_get_data):
        """Tests threat model generation with mock data (Rule 1)."""
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

    # --- Extended Test ---
    @patch("chimera_intel.core.automation.get_aggregated_data_for_target")
    def test_generate_threat_model_rule_2_cloud(self, mock_get_data):
        """
        Tests threat model generation for Rule 2 (Cloud S3 bucket).
        """
        mock_get_data.return_value = {
            "modules": {
                "cloud_osint_s3": {
                    "found_buckets": [{"name": "my-public-bucket", "is_public": True}]
                }
            }
        }
        result = generate_threat_model("example.com")
        self.assertEqual(len(result.potential_paths), 1)
        self.assertIn("S3 bucket: my-public-bucket", result.potential_paths[0].path[0])

    # --- Extended Test ---
    @patch("chimera_intel.core.automation.get_aggregated_data_for_target")
    def test_generate_threat_model_rule_3_leaks(self, mock_get_data):
        """
        Tests threat model generation for Rule 3 (Credential Leaks).
        """
        mock_get_data.return_value = {
            "modules": {
                "recon_credentials": {
                    "compromised_credentials": [
                        {"email": "test@example.com", "source_breach": "BreachA"}
                    ]
                }
            }
        }
        result = generate_threat_model("example.com")
        self.assertEqual(len(result.potential_paths), 1)
        self.assertIn(
            "leaked credential for user 'test@example.com'",
            result.potential_paths[0].path[0],
        )

    # --- Extended Test ---
    @patch("chimera_intel.core.automation.get_aggregated_data_for_target")
    def test_generate_threat_model_no_data(self, mock_get_data):
        """
        Tests threat model generation when no historical data is found.
        """
        mock_get_data.return_value = {}  # No data
        result = generate_threat_model("example.com")
        self.assertIsNotNone(result.error)
        self.assertIn("No historical data found", result.error)

    def test_analyze_behavioral_logs_correctly_separates_baseline(self):
        """
        Tests UEBA log analysis with a separate baseline and anomaly logs.
        """
        baseline_logs = (
            "timestamp,user,source_ip,action\n"
            "2025-09-08T10:00:00Z,user1,192.168.1.10,login_success\n"
            "2025-09-08T11:00:00Z,user1,192.168.1.10,read_file\n"
        )
        anomaly_logs = (
            "2025-09-09T03:00:00Z,user1,10.0.0.5,login_success\n"  # New IP, unusual hour
            "2025-09-09T10:00:00Z,user1,192.168.1.10,login_success\n"  # Normal login
        )
        combined_logs = baseline_logs + anomaly_logs

        with patch("builtins.open", mock_open(read_data=combined_logs)):
            with patch("os.path.exists", return_value=True):
                result = analyze_behavioral_logs("/fake/path/logs.csv")

                self.assertIsNotNone(result)
                self.assertEqual(result.total_anomalies_found, 2)
                self.assertIn("new source IP", result.anomalies[0].anomaly_description)
                self.assertIn("unusual time", result.anomalies[1].anomaly_description)

    # --- Extended Test ---
    @patch("os.path.exists", return_value=False)
    def test_analyze_behavioral_logs_file_not_found(self, mock_exists):
        """
        Tests UEBA analysis when the log file is not found.
        """
        result = analyze_behavioral_logs("nonexistent.csv")
        self.assertIsNotNone(result.error)
        self.assertIn("Log file not found", result.error)

    # --- Extended Test ---
    @patch("os.path.exists", return_value=True)
    def test_analyze_behavioral_logs_missing_headers(self, mock_exists):
        """
        Tests UEBA analysis when the log file has missing headers.
        """
        log_data = "header1,header2\nvalue1,value2"
        with patch("builtins.open", mock_open(read_data=log_data)):
            result = analyze_behavioral_logs("logs.csv")
            self.assertIsNotNone(result.error)
            self.assertIn(
                "Log file must contain headers: timestamp, user, source_ip",
                result.error,
            )

    # --- Extended Test ---
    @patch("os.path.exists", return_value=True)
    def test_analyze_behavioral_logs_parsing_error(self, mock_exists):
        """
        Tests UEBA analysis when the log file has a bad timestamp.
        """
        log_data = (
            "timestamp,user,source_ip\n"
            "2025-09-08T10:00:00Z,user1,192.168.1.10\n"  # Baseline
            "bad-timestamp,user1,10.0.0.5\n"  # Anomaly log with bad timestamp
        )
        with patch("builtins.open", mock_open(read_data=log_data)):
            result = analyze_behavioral_logs("logs.csv")
            # Should find the IP anomaly but skip the timestamp one
            self.assertEqual(result.total_anomalies_found, 1)
            self.assertIn("new source IP", result.anomalies[0].anomaly_description)

    @patch("chimera_intel.core.automation.os.path.exists", return_value=True)
    @patch("chimera_intel.core.automation.sync_client")
    def test_submit_to_virustotal_success(self, mock_client, mock_exists):
        """Tests VirusTotal submission with a realistic mock response."""
        with patch(
            "chimera_intel.core.automation.API_KEYS.virustotal_api_key", "fake_key"
        ):
            mock_get_response = MagicMock()
            mock_get_response.raise_for_status.return_value = None
            mock_get_response.json.return_value = {"data": "http://upload.url"}

            mock_post_response = MagicMock()
            mock_post_response.raise_for_status.return_value = None
            mock_post_response.json.return_value = {
                "data": {"id": "d8e8fca2dc0f896fd7cb4cb0031ba249-1630454400"}
            }

            mock_client.get.return_value = mock_get_response
            mock_client.post.return_value = mock_post_response

            with patch("builtins.open", mock_open(read_data=b"malware")):
                result = submit_to_virustotal("malicious.exe")

                self.assertIsInstance(result, VTSubmissionResult)
                self.assertEqual(result.response_code, 1)
                self.assertIn("d8e8fca2dc0f896fd7cb4cb0031ba249", result.permalink)
                self.assertIsNone(result.error)

    # --- Extended Test ---
    def test_submit_to_virustotal_no_api_key(self):
        """
        Tests VirusTotal submission when the API key is missing.
        """
        with patch("chimera_intel.core.automation.API_KEYS.virustotal_api_key", None):
            result = submit_to_virustotal("file.txt")
            self.assertIsNotNone(result.error)
            self.assertIn("VirusTotal API key not found", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.automation.API_KEYS.virustotal_api_key", "fake_key")
    @patch("chimera_intel.core.automation.os.path.exists", return_value=False)
    def test_submit_to_virustotal_file_not_found(self, mock_exists):
        """
        Tests VirusTotal submission when the file is not found.
        """
        result = submit_to_virustotal("nonexistent.exe")
        self.assertIsNotNone(result.error)
        self.assertIn("File not found", result.error)

    # --- Extended Test ---
    @patch("chimera_intel.core.automation.os.path.exists", return_value=True)
    @patch("chimera_intel.core.automation.sync_client")
    def test_submit_to_virustotal_api_failure(self, mock_client, mock_exists):
        """
        Tests VirusTotal submission when the API call fails.
        """
        with patch(
            "chimera_intel.core.automation.API_KEYS.virustotal_api_key", "fake_key"
        ):
            mock_client.get.side_effect = Exception("VT API is down")
            with patch("builtins.open", mock_open(read_data=b"malware")):
                result = submit_to_virustotal("malicious.exe")
                self.assertIsNotNone(result.error)
                self.assertIn("An API error occurred: VT API is down", result.error)

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
            mock_subprocess_run.assert_called_once()  # Stops after first failure

    # --- Extended Test ---
    @patch("chimera_intel.core.automation.logger.error")
    def test_run_workflow_no_target(self, mock_logger_error):
        """
        Tests workflow execution when the YAML file is missing 'target'.
        """
        mock_yaml_content = "steps:\n  - run: scan web {target}\n"
        with patch("builtins.open", mock_open(read_data=mock_yaml_content)):
            run_workflow("workflow.yaml")
            mock_logger_error.assert_called_with(
                "Workflow file must define a 'target'."
            )

    # --- Extended Test ---
    @patch("chimera_intel.core.automation.logger.error")
    def test_run_workflow_yaml_error(self, mock_logger_error):
        """
        Tests workflow execution when the YAML file is malformed.
        """
        with patch("builtins.open", side_effect=yaml.YAMLError("Bad YAML")):
            run_workflow("workflow.yaml")
            mock_logger_error.assert_called_with(
                "Failed to read or parse workflow file: Bad YAML"
            )

    # --- Extended Test: CLI Commands ---

    @patch("chimera_intel.core.automation.enrich_iocs", new_callable=AsyncMock)
    def test_cli_enrich_ioc(self, mock_enrich):
        """Tests the 'enrich-ioc' CLI command."""
        mock_enrich.return_value = MagicMock(model_dump=lambda: {"total_enriched": 1})
        result = runner.invoke(automation_app, ["enrich-ioc", "8.8.8.8"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_enriched": 1', result.stdout)

    @patch("chimera_intel.core.automation.generate_threat_model")
    def test_cli_threat_model(self, mock_generate):
        """Tests the 'threat-model' CLI command."""
        mock_generate.return_value = MagicMock(
            model_dump=lambda: {"target_domain": "test.com"}
        )
        result = runner.invoke(automation_app, ["threat-model", "test.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"target_domain": "test.com"', result.stdout)

    @patch("chimera_intel.core.automation.analyze_behavioral_logs")
    def test_cli_ueba(self, mock_analyze):
        """Tests the 'ueba' CLI command."""
        mock_analyze.return_value = MagicMock(
            model_dump=lambda: {"total_anomalies_found": 1}
        )
        result = runner.invoke(automation_app, ["ueba", "logs.csv"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_anomalies_found": 1', result.stdout)

    @patch("chimera_intel.core.automation.enrich_cves")
    def test_cli_enrich_cve(self, mock_enrich):
        """Tests the 'enrich-cve' CLI command."""
        mock_enrich.return_value = MagicMock(model_dump=lambda: {"total_enriched": 1})
        result = runner.invoke(automation_app, ["enrich-cve", "CVE-2023-0001"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_enriched": 1', result.stdout)

    @patch("chimera_intel.core.automation.run_workflow")
    def test_cli_workflow(self, mock_run):
        """Tests the 'workflow' CLI command."""
        result = runner.invoke(automation_app, ["workflow", "flow.yaml"])
        self.assertEqual(result.exit_code, 0)
        mock_run.assert_called_with("flow.yaml")

    @patch("chimera_intel.core.automation.submit_to_virustotal")
    def test_cli_virustotal(self, mock_submit):
        """Tests the 'virustotal' CLI command."""
        mock_submit.return_value = MagicMock(model_dump=lambda: {"response_code": 1})
        # FIX: Changed connect_app to automation_app
        result = runner.invoke(automation_app, ["virustotal", "file.txt"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"response_code": 1', result.stdout)

    @patch("chimera_intel.core.automation.submit_to_virustotal")
    @patch("chimera_intel.core.automation.save_or_print_results")
    def test_cli_virustotal_output_file(self, mock_save, mock_submit):
        """Tests the 'virustotal' CLI command with an --output file."""
        mock_dump = {"response_code": 1}
        mock_submit.return_value = MagicMock(model_dump=lambda: mock_dump)
        # FIX: Changed connect_app to automation_app
        result = runner.invoke(
            automation_app, ["virustotal", "file.txt", "--output", "out.json"]
        )
        self.assertEqual(result.exit_code, 0)
        mock_save.assert_called_with(mock_dump, "out.json")


if __name__ == "__main__":
    unittest.main()
