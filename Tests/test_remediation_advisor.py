# Tests/test_remediation_advisor.py

import unittest
import asyncio 
from unittest.mock import patch, Mock, AsyncMock 
from chimera_intel.core.remediation_advisor import (
    get_remediation_for_cve,
    get_remediation_for_hostile_infra,
    get_remediation_for_lookalike_domain,
    get_remediation_for_insider_threat,
    get_remediation_with_ai, # NEW: Import AI function
    _parse_ai_remediation, # NEW: Import parser
    RemediationPlanResult,
    RemediationStep
)
from chimera_intel.core.schemas import LegalTemplateResult

# Mock the API keys
@patch.dict(
    'chimera_intel.core.config_loader.API_KEYS',
    {'vulners_api_key': 'fake-vulners-key'}
)
class TestRemediationAdvisor(unittest.TestCase):

    @patch('chimera_intel.core.http_client.sync_client.post')
    def test_get_remediation_for_cve_success(self, mock_post):
        """Tests successful CVE remediation plan generation."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "result": "ok",
            "data": {
                "documents": {
                    "CVE-2021-44228": {
                        "title": "Apache Log4j RCE",
                        "description": "Log4Shell vulnerability. A workaround is available.",
                        "references": [
                            {
                                "refsource": "APACHE_ADVISORY",
                                "refurl": "https://logging.apache.org/log4j/2.x/security.html"
                            }
                        ]
                    }
                }
            }
        }
        mock_post.return_value = mock_response

        result = get_remediation_for_cve("CVE-2021-44228")

        self.assertIsNone(result.error)
        self.assertEqual(result.threat_identifier, "CVE-2021-44228")
        self.assertEqual(result.summary, "Apache Log4j RCE")
        self.assertEqual(len(result.steps), 3)
        
        # Check patch step
        patch_step = result.steps[1]
        self.assertEqual(patch_step.category, "Patch")
        self.assertEqual(patch_step.priority, 2)
        self.assertIn("https://logging.apache.org/log4j/2.x/security.html", patch_step.description)
        
        # Check mitigation step
        mitigation_step = result.steps[2]
        self.assertEqual(mitigation_step.category, "Mitigate")
        self.assertIn("workaround", mitigation_step.description)

    @patch('chimera_intel.core.http_client.sync_client.post')
    def test_get_remediation_for_cve_not_found(self, mock_post):
        """Tests plan generation for a CVE not found in Vulners."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "result": "ok",
            "data": {"documents": {}}
        }
        mock_post.return_value = mock_response

        result = get_remediation_for_cve("CVE-2000-9999")
        self.assertIsNotNone(result.error)
        self.assertIn("CVE not found", result.error)

    def test_get_remediation_for_hostile_infra(self):
        """Tests the static plan for hostile infrastructure."""
        details = {
            "port": 4444,
            "banner": "Metasploit",
            "asn": "AS12345"
        }
        result = get_remediation_for_hostile_infra("1.2.3.4", details)

        self.assertIsNone(result.error)
        self.assertEqual(result.threat_type, "Hostile Infrastructure")
        self.assertEqual(result.threat_identifier, "1.2.3.4")
        self.assertEqual(len(result.steps), 4)

        # Check block step
        block_step = result.steps[0]
        self.assertEqual(block_step.category, "Block")
        self.assertIn("1.2.3.4", block_step.description)
        self.assertIn("firewall", block_step.description)

        # Check investigate step
        investigate_step = result.steps[2]
        self.assertEqual(investigate_step.category, "Investigate")
        self.assertIn("Metasploit", investigate_step.description)

    @patch('chimera_intel.core.remediation_advisor.get_legal_escalation_template')
    def test_get_remediation_for_lookalike_domain(self, mock_get_template):
        """Tests the plan for lookalike domains, mocking the reused function."""
        mock_get_template.return_value = LegalTemplateResult(
            complaint_type="impersonation-report",
            template_body="[Template...]",
            contacts=["registrar@example.com"]
        )
        
        result = get_remediation_for_lookalike_domain(
            "chimera-intol.com",
            "Chimera Intel"
        )

        self.assertIsNone(result.error)
        self.assertEqual(result.threat_type, "Domain Impersonation")
        self.assertEqual(result.threat_identifier, "chimera-intol.com")
        self.assertEqual(len(result.steps), 4)

        # Check legal step from reused module
        legal_step = result.steps[3]
        self.assertEqual(legal_step.category, "Legal")
        self.assertIn("impersonation-report", legal_step.description)
        self.assertIn("registrar@example.com", legal_step.reference)

    def test_get_remediation_for_insider_threat(self):
        """Tests the static plan for insider threat risks."""
        factors = ["Potential code/credential leak on GitHub"]
        result = get_remediation_for_insider_threat("user@example.com", factors)

        self.assertIsNone(result.error)
        self.assertEqual(result.threat_type, "Insider Threat Risk")
        self.assertEqual(result.threat_identifier, "user@example.com")
        
        # Check escalate step
        escalate_step = result.steps[0]
        self.assertEqual(escalate_step.category, "Legal")
        self.assertIn("Security and Human Resources", escalate_step.description)

        # Check monitor step
        monitor_step = result.steps[1]
        self.assertEqual(monitor_step.category, "Monitor")
        self.assertIn("GitHub", monitor_step.description)

    def test_parse_ai_remediation_success(self):
        """Tests the AI response parser with categories."""
        ai_text = """
        Here is the plan:
        1. Block the sender's domain (fake-ceo.com) at the email gateway. [Block]
        2. Scan all mailboxes for the malicious email and quarantine it. [Response]
        3. Issue an internal alert to all employees. [Mitigate]
        """
        steps = _parse_ai_remediation(ai_text)
        self.assertEqual(len(steps), 3)
        self.assertEqual(steps[0].priority, 1)
        self.assertEqual(steps[0].description, "Block the sender's domain (fake-ceo.com) at the email gateway.")
        self.assertEqual(steps[0].category, "Block")
        self.assertEqual(steps[2].priority, 3)
        self.assertEqual(steps[2].category, "Mitigate")

    def test_parse_ai_remediation_fallback(self):
        """Tests the AI response parser fallback (no categories)."""
        ai_text = """
        - Block sender
        - Scan mailboxes
        """
        # Fallback parser just splits lines
        steps = _parse_ai_remediation(ai_text)
        self.assertEqual(len(steps), 2)
        self.assertEqual(steps[0].priority, 1)
        self.assertEqual(steps[0].description, "- Block sender")
        self.assertEqual(steps[0].category, "Investigate") # Default category

    @patch('chimera_intel.core.remediation_advisor.get_gemini_client')
    def test_get_remediation_with_ai_success(self, mock_get_client):
        """Tests the AI-driven remediation function."""
        # Mock the client and its async method
        mock_client = Mock()
        mock_client.generate_text_response = AsyncMock(
            return_value="1. Identify the leaked data. [Investigate]\n2. Revoke the exposed API key. [Block]"
        )
        mock_get_client.return_value = mock_client
        
        threat_type = "Data Leak"
        threat_details = "API key found in public GitHub repo."
        
        # Run the async function
        result = asyncio.run(get_remediation_with_ai(threat_type, threat_details))

        self.assertIsNone(result.error)
        self.assertEqual(result.threat_type, threat_type)
        self.assertEqual(len(result.steps), 2)
        self.assertEqual(result.steps[0].priority, 1)
        self.assertEqual(result.steps[0].category, "Investigate")
        self.assertEqual(result.steps[1].priority, 2)
        self.assertEqual(result.steps[1].description, "Revoke the exposed API key.")
        self.assertEqual(result.steps[1].category, "Block")

        # Verify the prompt was correct
        mock_client.generate_text_response.assert_called_once()
        prompt_arg = mock_client.generate_text_response.call_args[0][0]
        self.assertIn(threat_type, prompt_arg)
        self.assertIn(threat_details, prompt_arg)

    @patch('chimera_intel.core.remediation_advisor.get_gemini_client')
    def test_get_remediation_with_ai_no_client(self, mock_get_client):
        """Tests AI remediation when the client is not configured."""
        mock_get_client.return_value = None
        
        result = asyncio.run(get_remediation_with_ai("Test", "Test"))
        
        self.assertIsNotNone(result.error)
        self.assertIn("not configured", result.error)


if __name__ == '__main__':
    unittest.main()