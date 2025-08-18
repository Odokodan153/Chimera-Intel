import unittest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from chimera_intel.core.social_osint import find_social_profiles


class TestSocialOsint(unittest.TestCase):
    """Test cases for the social_osint module."""

    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    def test_find_social_profiles_success(self, mock_sherlock):
        """Tests a successful social media profile search."""
        # Mock the return value of the sherlock function

        mock_sherlock.return_value = {
            "GitHub": {
                "status": MagicMock(name="CLAIMED"),
                "url_user": "https://github.com/testuser",
            },
            "Twitter": {"status": MagicMock(name="AVAILABLE"), "url_user": ""},
        }

        result = asyncio.run(find_social_profiles("testuser"))

        self.assertEqual(len(result.found_profiles), 1)
        self.assertEqual(result.found_profiles[0].name, "GitHub")
        self.assertEqual(result.found_profiles[0].url, "https://github.com/testuser")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    def test_find_social_profiles_no_results(self, mock_sherlock):
        """Tests a search that yields no claimed profiles."""
        mock_sherlock.return_value = {
            "Twitter": {"status": MagicMock(name="AVAILABLE"), "url_user": ""}
        }

        result = asyncio.run(find_social_profiles("testuser_no_profiles"))
        self.assertEqual(len(result.found_profiles), 0)

    @patch("chimera_intel.core.social_osint.sherlock", new_callable=AsyncMock)
    def test_find_social_profiles_sherlock_error(self, mock_sherlock):
        """Tests the search when the sherlock library raises an exception."""
        # We can't easily mock an error inside the function,
        # but we can ensure it returns an empty list if sherlock fails unexpectedly.
        # This test is more conceptual for robustness.

        mock_sherlock.side_effect = Exception("Sherlock internal error")

        # We expect the function to handle it gracefully, though it might log an error.
        # For this test, we assume an empty result is the graceful outcome.

        result = asyncio.run(find_social_profiles("testuser"))
        self.assertEqual(len(result.found_profiles), 0)


if __name__ == "__main__":
    unittest.main()
