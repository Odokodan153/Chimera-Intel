import unittest
import logging
from unittest.mock import patch
from chimera_intel.core.schemas import Operation, Target
from chimera_intel.core.ethint import audit_operation


class TestETHINT(unittest.TestCase):
    """Test cases for the enhanced Ethical Governance & Compliance Engine."""

    def setUp(self):
        """Disable logging output during tests for a cleaner test run."""
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        """Re-enable logging after tests."""
        logging.disable(logging.NOTSET)

    @patch('chimera_intel.core.ethint.ETHICAL_FRAMEWORKS', {
        "data_privacy_gdpr": {
            "rules": [{"rule_id": "DP-01", "description": "Data processing must have a legal basis.", "severity": "CRITICAL"}]
        },
        "rules_of_engagement_default": {
            "rules": [
                {"rule_id": "ROE-01", "description": "Offensive operations must not target civilian infrastructure.", "severity": "CRITICAL"},
                {"rule_id": "ROE-02", "description": "Operations must have clear and sufficient justification.", "severity": "HIGH"}
            ]
        }
    })
    def test_compliant_operation(self):
        """Tests an operation that should pass all compliance checks."""
        compliant_op = Operation(
            operation_id="data-gather-001",
            operation_type="data_collection",
            targets=[Target(id="public-website.com", category="network")],
            justification="Standard market research and analysis.",
            targets_eu_citizen=True,
            has_legal_basis=True,
        )
        result = audit_operation(
            compliant_op, ["data_privacy_gdpr", "rules_of_engagement_default"]
        )
        self.assertTrue(result.is_compliant)
        self.assertEqual(len(result.violations), 0)

    @patch('chimera_intel.core.ethint.ETHICAL_FRAMEWORKS', {
        "rules_of_engagement_default": {
            "rules": [
                {"rule_id": "ROE-01", "description": "Offensive operations must not target civilian infrastructure.", "severity": "CRITICAL"}
            ]
        }
    })
    def test_non_compliant_offensive_operation(self):
        """Tests an offensive operation that targets civilian infrastructure."""
        non_compliant_op = Operation(
            operation_id="offensive-op-002",
            operation_type="network_disruption",
            is_offensive=True,
            targets=[
                Target(id="hospital-main-grid", category="civilian_infrastructure")
            ],
            justification="A test scenario.",
        )
        result = audit_operation(non_compliant_op, ["rules_of_engagement_default"])
        self.assertFalse(result.is_compliant)
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(result.violations[0].rule_id, "ROE-01")
        self.assertEqual(result.violations[0].severity, "CRITICAL")

    @patch('chimera_intel.core.ethint.ETHICAL_FRAMEWORKS', {
        "data_privacy_gdpr": {
            "rules": [{"rule_id": "DP-01", "description": "Data processing must have a legal basis.", "severity": "CRITICAL"}]
        }
    })
    def test_non_compliant_data_privacy_operation(self):
        """Tests a data collection operation that violates GDPR rules."""
        non_compliant_op = Operation(
            operation_id="privacy-breach-003",
            operation_type="data_collection",
            targets_eu_citizen=True,
            has_legal_basis=False,  # The critical part of the violation
            justification="Unauthorized data scraping.",
        )
        result = audit_operation(non_compliant_op, ["data_privacy_gdpr"])
        self.assertFalse(result.is_compliant)
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(result.violations[0].rule_id, "DP-01")
        self.assertEqual(result.violations[0].severity, "CRITICAL")

    @patch('chimera_intel.core.ethint.ETHICAL_FRAMEWORKS', {
        "rules_of_engagement_default": {
            "rules": [
                {"rule_id": "ROE-02", "description": "Operations must have clear and sufficient justification.", "severity": "HIGH"}
            ]
        }
    })
    def test_operation_with_insufficient_justification(self):
        """Tests an operation that fails due to a weak justification."""
        op_with_weak_justification = Operation(
            operation_id="weak-just-004",
            operation_type="network_scan",
            targets=[Target(id="192.168.1.1", category="network")],
            justification="Test",  # Too short, will fail ROE-02
        )
        result = audit_operation(
            op_with_weak_justification, ["rules_of_engagement_default"]
        )
        self.assertFalse(result.is_compliant)
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(result.violations[0].rule_id, "ROE-02")
        self.assertEqual(result.violations[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()