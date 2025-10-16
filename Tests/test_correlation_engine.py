import unittest
from unittest.mock import patch, Mock
from chimera_intel.core.correlation_engine import CorrelationEngine
from chimera_intel.core.schemas import Event


class TestCorrelationEngine(unittest.TestCase):
    """Test cases for the Core Correlation Engine."""

    def setUp(self):
        """Set up a mock plugin manager and config for each test."""
        self.mock_plugin_manager = Mock()
        self.config = {
            "correlation_rules": {
                "rules": [
                    {
                        "name": "New IP Scan",
                        "conditions": {"event_type": "footprint_scan"},
                        "actions": [
                            {
                                "type": "trigger_scan",
                                "params": [
                                    "defensive",
                                    "vuln",
                                    "run",
                                    "{details.new_ip}",
                                ],
                                "description": "New IP {details.new_ip} found for {target}",
                            }
                        ],
                    },
                    {
                        "name": "New Subdomain Scan",
                        "conditions": {"event_type": "footprint_scan"},
                        "actions": [
                            {
                                "type": "trigger_scan",
                                "params": [
                                    "scan",
                                    "web",
                                    "run",
                                    "{details.new_subdomain}",
                                ],
                                "description": "New subdomain {details.new_subdomain} found",
                            }
                        ],
                    },
                    {
                        "name": "Critical CVE TTP Mapping",
                        "conditions": {"event_type": "vulnerability_scan"},
                        "actions": [
                            {
                                "type": "ttp_lookup",
                                "trigger_on_find": {
                                    "params": ["ttp", "map-cve", "{details.cve_id}"]
                                },
                            }
                        ],
                    },
                ]
            }
        }
        self.engine = CorrelationEngine(self.mock_plugin_manager, self.config)

    @patch("chimera_intel.core.database.get_last_two_scans")
    def test_new_ip_triggers_vuln_scan(self, mock_get_scans):
        """Tests that a new IP in a footprint scan triggers a vulnerability scan."""
        # Arrange

        latest_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1", "2.2.2.2"]}}}
        previous_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}}
        mock_get_scans.return_value = (latest_scan, previous_scan)
        event = Event(
            event_type="footprint_scan",
            source="footprint_scanner",
            details={"new_ip": "2.2.2.2"},
        )

        # Act

        self.engine.process_event(event)

        # Assert

        self.mock_plugin_manager.run_command.assert_called_once_with(
            "defensive", "vuln", "run", "2.2.2.2"
        )

    @patch("chimera_intel.core.database.get_last_two_scans")
    def test_new_subdomain_triggers_web_scan(self, mock_get_scans):
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
        event = Event(
            event_type="footprint_scan",
            source="footprint_scanner",
            details={"new_subdomain": "new.example.com"},
        )

        # Act

        self.engine.process_event(event)

        # Assert

        self.mock_plugin_manager.run_command.assert_called_once_with(
            "scan", "web", "run", "new.example.com"
        )

    def test_critical_cve_triggers_ttp_map(self):
        """Tests that a critical CVE (CVSS >= 9.0) found in a vuln scan triggers a TTP mapping."""
        # Arrange

        event = Event(
            event_type="vulnerability_scan",
            source="vulnerability_scanner",
            details={"cve_id": "CVE-2023-1337", "cvss_score": 9.8},
        )

        # Act

        self.engine.process_event(event)

        # Assert

        self.mock_plugin_manager.run_command.assert_called_once_with(
            "ttp", "map-cve", "CVE-2023-1337"
        )

    @patch("chimera_intel.core.database.get_last_two_scans")
    def test_no_change_does_not_trigger_scan(self, mock_get_scans):
        """NEW: Tests that no scan is triggered if the footprint has not changed."""
        # Arrange

        latest_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}}
        previous_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}}
        mock_get_scans.return_value = (latest_scan, previous_scan)
        event = Event(
            event_type="footprint_scan",
            source="footprint_scanner",
            details={},
        )

        # Act

        self.engine.process_event(event)

        # Assert

        self.mock_plugin_manager.run_command.assert_not_called()

    @patch("chimera_intel.core.database.get_last_two_scans")
    def test_no_previous_scan_does_not_trigger(self, mock_get_scans):
        """NEW: Tests that no scan is triggered if there is no previous scan to compare against."""
        # Arrange

        latest_scan = {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}}
        # Simulate the first scan for a target

        mock_get_scans.return_value = (latest_scan, None)
        event = Event(
            event_type="footprint_scan",
            source="footprint_scanner",
            details={},
        )

        # Act

        self.engine.process_event(event)

        # Assert

        self.mock_plugin_manager.run_command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
