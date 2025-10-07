import unittest
from unittest.mock import patch, MagicMock

from chimera_intel.core.correlation_engine import run_correlations, _trigger_scan


class TestCorrelationEngine(unittest.TestCase):
    """Test cases for the Core Correlation Engine."""

    @patch("chimera_intel.core.correlation_engine.get_last_two_scans")
    @patch("chimera_intel.core.correlation_engine._trigger_scan")
    def test_new_ip_triggers_vuln_scan(self, mock_trigger, mock_get_scans):
        """Tests that a new IP in a footprint scan triggers a vulnerability scan."""
        # Arrange

        latest_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1", "2.2.2.2"]}}}
        previous_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}}
        mock_get_scans.return_value = (latest_scan, previous_scan)

        # Act

        run_correlations("example.com", "footprint", latest_scan)

        # Assert

        mock_trigger.assert_called_once_with(
            ["defensive", "vuln", "run", "2.2.2.2"],
            "New IP 2.2.2.2 found for example.com",
        )

    @patch("chimera_intel.core.correlation_engine.get_last_two_scans")
    @patch("chimera_intel.core.correlation_engine._trigger_scan")
    def test_new_subdomain_triggers_web_scan(self, mock_trigger, mock_get_scans):
        """Tests that a new subdomain triggers a web analysis scan."""
        # Arrange

        latest_scan = {
            "footprint": {
                "subdomains": {
                    "results": [
                        {"domain": "new.example.com"},
                        {"domain": "old.example.com"},
                    ]
                }
            }
        }
        previous_scan = {
            "footprint": {"subdomains": {"results": [{"domain": "old.example.com"}]}}
        }
        mock_get_scans.return_value = (latest_scan, previous_scan)

        # Act

        run_correlations("example.com", "footprint", latest_scan)

        # Assert

        mock_trigger.assert_called_once_with(
            ["scan", "web", "run", "new.example.com"],
            "New subdomain new.example.com found",
        )

    @patch("chimera_intel.core.correlation_engine._trigger_scan")
    def test_critical_cve_triggers_ttp_map(self, mock_trigger):
        """Tests that a critical CVE (CVSS >= 9.0) found in a vuln scan triggers a TTP mapping."""
        # Arrange

        scan_data = {
            "scanned_hosts": [
                {
                    "host": "1.2.3.4",
                    "open_ports": [
                        {
                            "vulnerabilities": [
                                {"id": "CVE-2023-1337", "cvss_score": 9.8}
                            ]
                        }
                    ],
                }
            ]
        }

        # Act

        run_correlations("1.2.3.4", "vulnerability_scanner", scan_data)

        # Assert

        mock_trigger.assert_called_once_with(
            ["ttp", "map-cve", "CVE-2023-1337"],
            "Critical CVE CVE-2023-1337 found on 1.2.3.4",
        )

    @patch("chimera_intel.core.correlation_engine.get_last_two_scans")
    @patch("chimera_intel.core.correlation_engine._trigger_scan")
    def test_no_change_does_not_trigger_scan(self, mock_trigger, mock_get_scans):
        """NEW: Tests that no scan is triggered if the footprint has not changed."""
        # Arrange

        latest_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}}
        previous_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}}
        mock_get_scans.return_value = (latest_scan, previous_scan)

        # Act

        run_correlations("example.com", "footprint", latest_scan)

        # Assert

        mock_trigger.assert_not_called()

    @patch("chimera_intel.core.correlation_engine.get_last_two_scans")
    @patch("chimera_intel.core.correlation_engine._trigger_scan")
    def test_no_previous_scan_does_not_trigger(self, mock_trigger, mock_get_scans):
        """NEW: Tests that no scan is triggered if there is no previous scan to compare against."""
        # Arrange

        latest_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}}
        # Simulate the first scan for a target

        mock_get_scans.return_value = (latest_scan, None)

        # Act

        run_correlations("example.com", "footprint", latest_scan)

        # Assert

        mock_trigger.assert_not_called()

    @patch("chimera_intel.core.correlation_engine.subprocess.Popen")
    def test_internal_trigger_scan_helper_calls_subprocess(self, mock_popen):
        """Tests the internal _trigger_scan helper function to ensure it formats and calls the command correctly."""
        # Arrange

        command = ["scan", "footprint", "run", "test.com"]
        reason = "Test reason"

        # Act

        _trigger_scan(command, reason)

        # Assert

        mock_popen.assert_called_once()
        # Check the arguments passed to Popen

        called_args = mock_popen.call_args[0][0]
        self.assertEqual(called_args, ["chimera"] + command)


if __name__ == "__main__":
    unittest.main()
