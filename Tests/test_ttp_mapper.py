import unittest
import json
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.ttp_mapper import ttp_app
from chimera_intel.core.schemas import TTPMappingResult

runner = CliRunner()


class TestTtpMapper(unittest.TestCase):
    """Test cases for the Adversary Emulation & TTP Mapping module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.ttp_mapper.MitreAttackData")
    def test_map_cves_to_ttp_success(self, mock_mitre_data):
        """Tests a successful mapping of a CVE to an ATT&CK technique."""
        # Arrange

        mock_attack_instance = mock_mitre_data.return_value

        # Create a mock technique object with the necessary attributes

        mock_technique = MagicMock()
        mock_technique.name = "Phishing"
        mock_technique.external_references = [MagicMock(external_id="T1566")]
        mock_technique.kill_chain_phases = [MagicMock(name="initial-access")]

        mock_attack_instance.get_techniques_by_cve_id.return_value = [mock_technique]

        # Act

        from chimera_intel.core.ttp_mapper import map_cves_to_ttp

        result = map_cves_to_ttp(["CVE-2023-1234"])

        # Assert

        self.assertIsInstance(result, TTPMappingResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.mapped_techniques), 1)
        self.assertEqual(result.mapped_techniques[0].cve_id, "CVE-2023-1234")
        self.assertEqual(result.mapped_techniques[0].technique_id, "T1566")
        self.assertEqual(result.mapped_techniques[0].technique_name, "Phishing")
        self.assertEqual(result.mapped_techniques[0].tactic, "initial-access")

    @patch("chimera_intel.core.ttp_mapper.MitreAttackData")
    def test_map_cves_to_ttp_no_mapping_found(self, mock_mitre_data):
        """Tests the case where a CVE has no corresponding ATT&CK technique."""
        # Arrange

        mock_attack_instance = mock_mitre_data.return_value
        mock_attack_instance.get_techniques_by_cve_id.return_value = (
            []
        )  # No techniques found

        # Act

        from chimera_intel.core.ttp_mapper import map_cves_to_ttp

        result = map_cves_to_ttp(["CVE-2000-0001"])

        # Assert

        self.assertEqual(len(result.mapped_techniques), 0)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.ttp_mapper.MitreAttackData")
    def test_map_cves_to_ttp_library_error(self, mock_mitre_data):
        """Tests error handling if the mitreattack-python library fails."""
        # Arrange

        mock_mitre_data.side_effect = Exception("Failed to load ATT&CK data")

        # Act

        from chimera_intel.core.ttp_mapper import map_cves_to_ttp

        result = map_cves_to_ttp(["CVE-2023-1234"])

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Failed to load ATT&CK data", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.ttp_mapper.save_scan_to_db")
    @patch("chimera_intel.core.ttp_mapper.MitreAttackData")
    def test_cli_map_cve_success(self, mock_mitre_data, mock_save_scan_to_db):
        """Tests a successful run of the 'ttp map-cve' CLI command."""
        # Arrange

        mock_attack_instance = mock_mitre_data.return_value
        mock_technique = MagicMock()
        mock_technique.name = "Phishing"
        mock_technique.external_references = [MagicMock(external_id="T1566")]
        mock_technique.kill_chain_phases = [MagicMock(name="initial-access")]
        mock_attack_instance.get_techniques_by_cve_id.return_value = [mock_technique]

        # Act

        result = runner.invoke(ttp_app, ["map-cve", "CVE-2023-1234"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output["total_cves_analyzed"], 1)
        self.assertEqual(output["mapped_techniques"][0]["technique_id"], "T1566")
        mock_save_scan_to_db.assert_called_with(
            target="CVE-2023-1234",
            module="ttp_mapper_cve",
            data=output,
        )


if __name__ == "__main__":
    unittest.main()
