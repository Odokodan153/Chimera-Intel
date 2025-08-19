import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.social_osint import find_social_profiles

# FIX: Patch SitesInformation at the class level to prevent network calls during all tests


@patch("chimera_intel.core.social_osint.SitesInformation")
class TestSocialOsint(unittest.TestCase):
    """Test cases for the social_osint module."""

    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    def test_find_social_profiles_success(self, mock_sherlock, mock_sites_info):
        """Tests a successful social media profile search."""
        # This helper class mimics the structure of the Sherlock enum

        class MockStatus:
            def __init__(self, name):
                self.name = name

        # Mock the return value of the sherlock function

        mock_sherlock.return_value = {
            "GitHub": {
                "status": MockStatus("CLAIMED"),
                "url_user": "https://github.com/testuser",
            },
            "Twitter": {"status": MockStatus("AVAILABLE"), "url_user": ""},
        }

        result = asyncio.run(find_social_profiles("testuser"))

        self.assertEqual(len(result.found_profiles), 1)
        self.assertEqual(result.found_profiles[0].name, "GitHub")
        self.assertEqual(result.found_profiles[0].url, "https://github.com/testuser")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    def test_find_social_profiles_no_results(self, mock_sherlock, mock_sites_info):
        """Tests a search that yields no claimed profiles."""

        class MockStatus:
            def __init__(self, name):
                self.name = name

        mock_sherlock.return_value = {
            "Twitter": {"status": MockStatus("AVAILABLE"), "url_user": ""}
        }

        result = asyncio.run(find_social_profiles("testuser_no_profiles"))
        self.assertEqual(len(result.found_profiles), 0)

    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    def test_find_social_profiles_sherlock_error(self, mock_sherlock, mock_sites_info):
        """Tests the search when the sherlock library raises an exception."""
        # This test is more conceptual for robustness, ensuring the function doesn't crash.

        mock_sherlock.side_effect = Exception("Sherlock internal error")

        # We expect the function to handle the error gracefully and return an empty list.

        result = asyncio.run(find_social_profiles("testuser"))
        self.assertEqual(len(result.found_profiles), 0)
        self.assertIsNotNone(result.error)
        self.assertIn("Sherlock internal error", result.error)


if __name__ == "__main__":
    unittest.main()
