import unittest
from unittest.mock import patch, mock_open
from typer.testing import CliRunner

# Import the specific app for this module to test the CLI command directly


from chimera_intel.core.threat_hunter import hunt_for_iocs_in_log, threat_hunter_app
from chimera_intel.core.schemas import (
    ThreatActorIntelResult,
    ThreatActor,
    ThreatHuntResult,
)

runner = CliRunner()


class TestThreatHunter(unittest.TestCase):
    """Test cases for the Threat Hunter module."""

    @patch("chimera_intel.core.threat_hunter.get_threat_actor_profile")
    @patch("chimera_intel.core.threat_hunter.os.path.exists", return_value=True)
    def test_hunt_for_iocs_in_log_success(self, mock_exists, mock_get_profile):
        """Tests a successful threat hunt where IOCs are found."""
        # Arrange

        mock_actor = ThreatActor(
            name="TestAPT",
            known_indicators=["1.2.3.4", "evil.com"],
        )
        mock_get_profile.return_value = ThreatActorIntelResult(actor=mock_actor)

        log_content = (
            "timestamp,message\n"
            "2025-01-01T12:00:00Z,Connection from 192.168.1.1\n"
            "2025-01-01T12:01:00Z,Connection from evil.com\n"
            "2025-01-01T12:02:00Z,Connection from 1.2.3.4\n"
        )

        with patch("builtins.open", mock_open(read_data=log_content)):
            # Act

            result = hunt_for_iocs_in_log("fake.log", "TestAPT")
        # Assert

        self.assertIsInstance(result, ThreatHuntResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_iocs_found, 2)
        self.assertEqual(len(result.detected_iocs), 2)
        self.assertEqual(result.detected_iocs[0].ioc, "evil.com")
        self.assertEqual(result.detected_iocs[1].ioc, "1.2.3.4")

    @patch("chimera_intel.core.threat_hunter.os.path.exists", return_value=True)
    @patch("chimera_intel.core.threat_hunter.get_threat_actor_profile")
    def test_hunt_for_iocs_actor_not_found(self, mock_get_profile, mock_exists):
        """Tests the case where the threat actor profile cannot be found."""
        # Arrange

        mock_get_profile.return_value = ThreatActorIntelResult(error="Actor not found.")

        # Act

        with patch("builtins.open", mock_open(read_data="log data")):
            result = hunt_for_iocs_in_log("fake.log", "UnknownAPT")
        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Could not retrieve profile", result.error)

    def test_hunt_for_iocs_log_file_not_found(self):
        """Tests the case where the log file does not exist."""
        # Act

        result = hunt_for_iocs_in_log("nonexistent.log", "TestAPT")

        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Log file not found", result.error)

    # --- CLI Command Tests ---

    @patch("chimera_intel.core.threat_hunter.hunt_for_iocs_in_log")
    def test_cli_threat_hunt_success(self, mock_hunt):
        """Tests the 'cybint threat-hunt' CLI command."""
        # Arrange

        mock_hunt.return_value.model_dump.return_value = {"total_iocs_found": 1}

        # Act: Invoke the command through the specific threat_hunter_app
        # FIX: When a Typer app has a single command, you don't need to specify its name.
        # The runner was incorrectly interpreting "run" as a value for an argument.

        result = runner.invoke(
            threat_hunter_app,
            [
                "--log-file",
                "test.log",
                "--actor",
                "TestAPT",
            ],
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"total_iocs_found": 1', result.stdout)
        mock_hunt.assert_called_with("test.log", "TestAPT")


if __name__ == "__main__":
    unittest.main()
