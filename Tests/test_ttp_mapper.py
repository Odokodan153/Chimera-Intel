import unittest
from unittest.mock import patch, MagicMock

from chimera_intel.core.ttp_mapper import map_cves_to_ttp
from chimera_intel.core.schemas import TTPMappingResult


class TestTTPMapper(unittest.TestCase):
    """Test cases for the ttp_mapper module."""

    @patch("chimera_intel.core.ttp_mapper.MitreAttackData")
    def test_map_cves_to_ttp_success(self, mock_mitre_data):
        """Tests a successful CVE to TTP mapping by mocking the MITRE library."""
        # Arrange

        mock_attack = mock_mitre_data.return_value

        # Create mock Technique and KillChainPhase objects

        mock_phase = MagicMock(name="Execution")
        mock_tech = MagicMock(
            name="Exploit Public-Facing Application",
            external_references=[MagicMock(external_id="T1190")],
            kill_chain_phases=[mock_phase],
        )

        mock_attack.get_techniques_by_cve_id.return_value = [mock_tech]

        # Act

        result = map_cves_to_ttp(["CVE-2021-44228"])

        # Assert

        self.assertIsInstance(result, TTPMappingResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.mapped_techniques), 1)
        self.assertEqual(result.mapped_techniques[0].technique_id, "T1190")
        self.assertEqual(result.mapped_techniques[0].tactic, "Execution")


if __name__ == "__main__":
    unittest.main()
