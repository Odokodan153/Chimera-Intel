import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError

from chimera_intel.core.threat_actor_intel import get_threat_actor_profile
from chimera_intel.core.schemas import ThreatActorIntelResult, ThreatActor


class TestThreatActorIntel(unittest.TestCase):
    """Test cases for the Threat Actor Intelligence module."""

    @patch("chimera_intel.core.threat_actor_intel.sync_client.get")
    def test_get_threat_actor_profile_success(self, mock_get):
        """Tests a successful threat actor profile retrieval from the OTX API."""
        # --- Arrange: Mock the API response ---

        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [
                {
                    "tags": ["APT28", "Fancy Bear", "government"],
                    "attack_ids": [
                        {"id": "T1566", "name": "Phishing", "tactic": "initial-access"}
                    ],
                    "indicators": [
                        {"indicator": "1.2.3.4"},
                        {"indicator": "evil.com"},
                    ],
                },
                {
                    "tags": ["Sofacy Group", "defense"],
                    "attack_ids": [
                        {
                            "id": "T1059",
                            "name": "Command and Control",
                            "tactic": "execution",
                        }
                    ],
                    "indicators": [{"indicator": "5.6.7.8"}],
                },
            ]
        }
        mock_get.return_value = mock_response

        # --- Act ---

        with patch(
            "chimera_intel.core.threat_actor_intel.API_KEYS.otx_api_key", "fake_key"
        ):
            result = get_threat_actor_profile("APT28")
        # --- Assert ---

        self.assertIsInstance(result, ThreatActorIntelResult)
        self.assertIsNone(result.error)
        self.assertIsInstance(result.actor, ThreatActor)

        actor = result.actor
        self.assertEqual(actor.name, "APT28")
        # Verify aggregation of aliases and industries

        self.assertIn("Fancy Bear", actor.aliases)
        self.assertIn("Sofacy Group", actor.aliases)
        self.assertIn("Government", actor.targeted_industries)
        self.assertEqual(len(actor.known_ttps), 2)
        self.assertEqual(actor.known_ttps[0].tactic, "Initial Access")
        self.assertEqual(len(actor.known_indicators), 3)
        self.assertIn("evil.com", actor.known_indicators)

    @patch("chimera_intel.core.threat_actor_intel.sync_client.get")
    def test_get_threat_actor_profile_no_results(self, mock_get):
        """Tests the function's behavior when the API returns no results."""
        # --- Arrange ---

        mock_response = MagicMock(spec=Response)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"results": []}  # Empty results list
        mock_get.return_value = mock_response

        # --- Act ---

        with patch(
            "chimera_intel.core.threat_actor_intel.API_KEYS.otx_api_key", "fake_key"
        ):
            result = get_threat_actor_profile("UnknownGroup")
        # --- Assert ---

        self.assertIsInstance(result, ThreatActorIntelResult)
        self.assertIsNotNone(result.error)
        self.assertIn("No intelligence pulses found", result.error)
        self.assertIsNone(result.actor)

    def test_get_threat_actor_profile_no_api_key(self):
        """Tests that the function returns an error if the OTX API key is not configured."""
        # --- Act ---

        with patch("chimera_intel.core.threat_actor_intel.API_KEYS.otx_api_key", None):
            result = get_threat_actor_profile("APT28")
        # --- Assert ---

        self.assertIsInstance(result, ThreatActorIntelResult)
        self.assertIsNotNone(result.error)
        self.assertIn("OTX API key (OTX_API_KEY) is not configured", result.error)

    @patch("chimera_intel.core.threat_actor_intel.sync_client.get")
    def test_get_threat_actor_profile_api_error(self, mock_get):
        """Tests the function's error handling when the API call fails."""
        # --- Arrange ---

        mock_get.side_effect = RequestError("Network connection failed")

        # --- Act ---

        with patch(
            "chimera_intel.core.threat_actor_intel.API_KEYS.otx_api_key", "fake_key"
        ):
            result = get_threat_actor_profile("APT28")
        # --- Assert ---

        self.assertIsInstance(result, ThreatActorIntelResult)
        self.assertIsNotNone(result.error)
        self.assertIn("An API error occurred", result.error)


if __name__ == "__main__":
    unittest.main()
