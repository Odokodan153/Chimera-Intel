import unittest
from unittest.mock import Mock, patch
from chimera_intel.core.correlation_engine import (
    CorrelationEngine,
    AlertPrioritizationEngine,
)
from chimera_intel.core.schemas import Event


class TestCorrelationEngine(unittest.TestCase):
    """Test cases for the Core Correlation Engine."""

    def setUp(self):
        """Set up a mock plugin manager and config for each test."""
        self.mock_plugin_manager = Mock()
        self.config = {
            # --- NEW: IFTTT Pipelines ---
            "automation_pipelines": {
                "pipelines": [
                    {
                        "name": "Pipeline 1: New IP Scan",
                        # 'IF' trigger:
                        "trigger": {"event.event_type": "footprint_scan"},
                        # 'THEN-THAT' actions:
                        "actions": [
                            {
                                "type": "trigger_scan",
                                "params": [
                                    "defensive",
                                    "vuln",
                                    "run",
                                    "{details.new_ip}",
                                ],
                            }
                        ],
                    },
                    {
                        "name": "Pipeline 2: Critical CVE TTP",
                        "trigger": {
                            "event.event_type": "vulnerability_scan",
                            # NEW: Trigger on high priority
                            "priority": "High",
                        },
                        "actions": [
                            {
                                "type": "ttp_lookup",
                                "trigger_on_find": {
                                    "params": ["ttp", "map-cve", "{cve_id}"]
                                },
                            }
                        ],
                    },
                    # --- NEW: Cross-Module Correlation Pipeline ---
                    {
                        "name": "Pipeline 3: Cross-Module Finance to Personnel",
                        "trigger": {
                            # 'IF' a finance event happens...
                            "domain": "finance",
                            "event.event_type": "finance_anomaly",
                            "event.details.is_large_transfer": True,
                        },
                        "actions": [
                            {
                                # 'THEN-THAT' trigger a personnel scan
                                "type": "trigger_scan",
                                "params": [
                                    "personnel",
                                    "check_user",
                                    "{details.user}", # Get user from finance event
                                ],
                            }
                        ],
                    },
                ]
            },
            # --- NEW: Prioritization Weights ---
            "prioritization_weights": {
                "impact": 0.6,
                "confidence": 0.3,
                "relevance": 0.1,
            },
            "ttp_knowledge_base": {
                "CVE-2023-1337": {"name": "Mock TTP", "attack_id": "T1234"}
            },
        }
        self.engine = CorrelationEngine(self.mock_plugin_manager, self.config)

    # --- NEW: Test for Prioritization Engine ---
    def test_alert_prioritization_engine(self):
        """Tests the new AlertPrioritizationEngine directly."""
        engine = AlertPrioritizationEngine(
            {"impact": 0.6, "confidence": 0.3, "relevance": 0.1}
        )
        
        # High impact event
        high_event = Event(
            event_type="vulnerability_scan",
            source="vulnerability_scanner",
            details={"cvss_score": 10.0, "is_critical_asset": True},
        )
        high_alert = engine.prioritize_alert(high_event)
        
        # Low impact event
        low_event = Event(
            event_type="vulnerability_scan",
            source="social_media_listener", # Low confidence
            details={"cvss_score": 1.0},
        )
        low_alert = engine.prioritize_alert(low_event)

        self.assertEqual(high_alert.priority, "High")
        self.assertEqual(low_alert.priority, "Low")
        self.assertGreater(high_alert.ranking_score, low_alert.ranking_score)
        self.assertAlmostEqual(high_alert.impact, 1.0)
        self.assertAlmostEqual(high_alert.confidence, 0.9)
        self.assertAlmostEqual(low_alert.impact, 0.1)
        self.assertAlmostEqual(low_alert.confidence, 0.5)


    def test_new_ip_triggers_vuln_scan(self):
        """Tests that a new IP triggers Pipeline 1."""
        event = Event(
            event_type="footprint_scan",
            source="footprint_scanner",
            details={"new_ip": "2.2.2.2"},
        )
        self.engine.process_event(event)
        self.mock_plugin_manager.run_command.assert_called_with(
            "defensive", "vuln", "run", "2.2.2.2"
        )

    def test_critical_cve_triggers_ttp_map(self):
        """Tests that a critical CVE triggers Pipeline 2."""
        event = Event(
            event_type="vulnerability_scan",
            source="vulnerability_scanner",
            details={"cve_id": "CVE-2023-1337", "cvss_score": 9.8},
        )
        self.engine.process_event(event)
        
        # Assert: TTP lookup was called because the event was prioritized as 'High'
        self.mock_plugin_manager.run_command.assert_called_once_with(
            "ttp", "map-cve", "CVE-2023-1337"
        )

    def test_low_priority_cve_does_not_trigger(self):
        """Tests that a low-priority CVE does *not* trigger Pipeline 2."""
        self.mock_plugin_manager.reset_mock()
        event = Event(
            event_type="vulnerability_scan",
            source="vulnerability_scanner",
            details={"cve_id": "CVE-2023-0001", "cvss_score": 3.0}, # Low score
        )
        self.engine.process_event(event)
        
        # Assert: No command was called because priority was not 'High'
        self.mock_plugin_manager.run_command.assert_not_called()

    # --- NEW: Test for Cross-Module Correlation ---
    def test_cross_module_correlation_finance_to_personnel(self):
        """Tests Pipeline 3: A finance event triggers a personnel scan."""
        event = Event(
            event_type="finance_anomaly",
            source="finance_tracker",
            details={"is_large_transfer": True, "user": "john.doe"},
        )
        self.engine.process_event(event)
        
        # Assert: The finance event triggered a "personnel" plugin command
        self.mock_plugin_manager.run_command.assert_called_once_with(
            "personnel", "check_user", "john.doe"
        )


if __name__ == "__main__":
    unittest.main()