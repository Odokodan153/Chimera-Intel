import unittest
from unittest.mock import patch

from chimera_intel.core.correlation_engine import run_correlations


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
            "footprint": {"subdomains": {"results": [{"domain": "new.example.com"}]}}
        }
        previous_scan = {"footprint": {"subdomains": {"results": []}}}
        mock_get_scans.return_value = (latest_scan, previous_scan)

        # Act

        run_correlations("example.com", "footprint", latest_scan)

        # Assert

        mock_trigger.assert_called_with(
            ["scan", "web", "run", "new.example.com"],
            "New subdomain new.example.com found",
        )

    @patch("chimera_intel.core.correlation_engine._trigger_scan")
    def test_critical_cve_triggers_ttp_map(self, mock_trigger):
        """Tests that a critical CVE triggers a TTP mapping."""
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
            ["ttp", "map-cve", "CVE-2023-1337"], "Critical CVE CVE-2023-1337 found"
        )

    @patch("chimera_intel.core.correlation_engine.subprocess.Popen")
    def test_trigger_scan_calls_subprocess(self, mock_popen):
        """Tests the internal _trigger_scan helper function."""
        from chimera_intel.core.correlation_engine import _trigger_scan

        command = ["scan", "footprint", "run", "test.com"]
        _trigger_scan(command, "Test reason")

        mock_popen.assert_called_once()
        called_args = mock_popen.call_args[0][0]
        self.assertEqual(called_args, ["chimera"] + command)


if __name__ == "__main__":
    unittest.main()
