"""
(NEW) Tests for the OSINT Fusion Hub Module.
"""
import unittest
import json
import os
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.osint_fusion import (
    process_scraped_profiles,
    process_scraped_jobs,
    osint_app
)
from chimera_intel.core.schemas import ScrapedProfile, ScrapedJobPosting

runner = CliRunner()

class TestOsintFusion(unittest.TestCase):

    @patch("chimera_intel.core.osint_fusion.map_network_link")
    def test_process_scraped_profiles(self, mock_map_link):
        """Tests that profile data is correctly processed into network links."""
        # Arrange
        profile_data = [
            ScrapedProfile(
                full_name="Jane Doe",
                profile_url="http://linkedin.com/in/janedoe",
                current_company="Acme Corp",
                current_title="Lead Engineer",
                education=["Tech University"],
                past_roles=[
                    {"title": "Dev", "company": "Globex"}
                ]
            )
        ]
        
        # Act
        links_created = process_scraped_profiles(profile_data)
        
        # Assert
        self.assertEqual(links_created, 3)
        
        # Check that humint.map_network_link was called with the right data
        mock_map_link.assert_any_call("Jane Doe", "Works at as Lead Engineer", "Acme Corp")
        mock_map_link.assert_any_call("Jane Doe", "Worked at as Dev", "Globex")
        mock_map_link.assert_any_call("Jane Doe", "Educated at", "Tech University")

    def test_process_scraped_jobs(self):
        """Tests that job posting data is processed."""
        # Arrange
        job_data = [
            ScrapedJobPosting(
                company_name="Acme Corp",
                job_title="New Analyst",
                url="http://jobs.com/1"
            )
        ]
        
        # Act
        count = process_scraped_jobs(job_data)
        
        # Assert
        self.assertEqual(count, 1)
        # We can't assert much more as this function just prints,
        # but this confirms it runs and processes the item.

    @patch("chimera_intel.core.osint_fusion.process_scraped_profiles")
    def test_cli_fuse_profiles_success(self, mock_process_profiles):
        """Tests the CLI command for fusing profiles from a JSON file."""
        
        # Create a temporary JSON file
        test_data = [{
            "full_name": "John Smith",
            "profile_url": "http://example.com"
        }]
        test_filename = "test_profiles.json"
        
        with open(test_filename, 'w') as f:
            json.dump(test_data, f)
            
        try:
            result = runner.invoke(osint_app, ["fuse-profiles", test_filename])
            
            self.assertEqual(result.exit_code, 0)
            
            # Check that the processor was called with the correctly parsed data
            mock_process_profiles.assert_called_once()
            called_arg = mock_process_profiles.call_args[0][0]
            self.assertIsInstance(called_arg, list)
            self.assertEqual(len(called_arg), 1)
            self.assertIsInstance(called_arg[0], ScrapedProfile)
            self.assertEqual(called_arg[0].full_name, "John Smith")
            
        finally:
            # Clean up the temp file
            if os.path.exists(test_filename):
                os.remove(test_filename)

    def test_cli_fuse_profiles_file_not_found(self):
        """Tests that the CLI handles a missing file."""
        result = runner.invoke(osint_app, ["fuse-profiles", "non_existent_file.json"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("does not exist", result.stdout)