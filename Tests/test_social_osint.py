import unittest
import json 
from unittest.mock import patch, AsyncMock
from typer.testing import CliRunner

from chimera_intel.core.social_osint import find_social_profiles, social_osint_app
from chimera_intel.core.schemas import SocialOSINTResult, SocialProfile

# Mock the Sherlock result status enum
class MockClaimedStatus:
    name = "CLAIMED"

# --- Revert to default runner initialization ---
runner = CliRunner()


class TestSocialOsint(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Social Media OSINT (Sherlock) module."""

    # --- Function Tests (These are correct as-is) ---

    @patch("chimera_intel.core.social_osint.SitesInformation")
    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    async def test_find_social_profiles_success(self, mock_sherlock, mock_sites_info):
        """Tests a successful social media profile search."""
        # Arrange
        mock_sites_info.return_value = {}  # Mock away the file access
        mock_sherlock.return_value = {
            "GitHub": {
                "status": MockClaimedStatus(),
                "url_user": "https.github.com/testuser",
            },
            "Twitter": {
                "status": MockClaimedStatus(),
                "url_user": "https.twitter.com/testuser",
            },
        }

        # Act
        result = await find_social_profiles("testuser")

        # Assert
        self.assertIsInstance(result, SocialOSINTResult)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.found_profiles), 2)
        profile_names = {p.name for p in result.found_profiles}
        self.assertIn("GitHub", profile_names)
        self.assertIn("Twitter", profile_names)

    @patch("chimera_intel.core.social_osint.SitesInformation")
    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    async def test_find_social_profiles_no_results(
        self, mock_sherlock, mock_sites_info
    ):
        """Tests a search that yields no results."""
        # Arrange
        mock_sites_info.return_value = {}
        mock_sherlock.return_value = {}

        # Act
        result = await find_social_profiles("nonexistentuser")

        # Assert
        self.assertEqual(len(result.found_profiles), 0)
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.social_osint.SitesInformation")
    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    async def test_find_social_profiles_sherlock_error(
        self, mock_sherlock, mock_sites_info
    ):
        """Tests error handling when the Sherlock library raises an exception."""
        # Arrange
        mock_sites_info.return_value = {}
        mock_sherlock.side_effect = Exception("Network timeout")

        # Act
        result = await find_social_profiles("testuser")

        # Assert
        self.assertIsNotNone(result.error)
        self.assertIn("Network timeout", result.error)

    # --- CLI Tests ---

    @patch("chimera_intel.core.social_osint.typer.echo")
    @patch("chimera_intel.core.social_osint.save_scan_to_db") # <-- Mock the DB call
    @patch("chimera_intel.core.social_osint.find_social_profiles", new_callable=AsyncMock)
    def test_cli_run_social_osint_scan_success(self, mock_find_profiles, mock_save_db, mock_echo):
        """Tests a successful run of the 'social-osint run' CLI command."""
        
        mock_data = SocialOSINTResult(
            username="cliuser",
            found_profiles=[
                SocialProfile(name="GitLab", url="https.gitlab.com/cliuser")
            ],
        )
        
        mock_find_profiles.return_value = mock_data
       
        # --- FIX: The command MUST include the 'run' subcommand ---
        result = runner.invoke(social_osint_app, ["run", "cliuser"])
        # --- End Fix ---

        # Assert
        self.assertEqual(result.exit_code, 0, result.stdout)
        
        # Check that the function was called correctly
        mock_find_profiles.assert_called_once_with("cliuser")
        
        # Check that the DB save function was called
        mock_save_db.assert_called_once()
        
        # Check that typer.echo was called with the correct JSON
        mock_echo.assert_called_once()
        json_output_str = mock_echo.call_args[0][0]
        output = json.loads(json_output_str)

        self.assertEqual(output["username"], "cliuser")
        self.assertEqual(len(output["found_profiles"]), 1)
        self.assertEqual(output["found_profiles"][0]["name"], "GitLab")

    def test_cli_run_no_username(self):
        """Tests that the CLI command fails if no username is provided."""
        
        # The 'run' subcommand is passed, but the required 'USERNAME' is not.
        result = runner.invoke(social_osint_app, ["run"])
        
        self.assertNotEqual(result.exit_code, 0)
        
        # --- FIX: Correct the assertion string. ---
        # Typer's rich formatting doesn't prefix "Error: " to the message itself.
        output = result.stderr
        self.assertIn("Missing argument 'USERNAME'.", output)
        # --- End Fix ---

if __name__ == "__main__":
    unittest.main()