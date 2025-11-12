import unittest
import json
from unittest.mock import patch, AsyncMock
from typer.testing import CliRunner
import respx
import httpx
import pytest

from chimera_intel.core.social_osint import (
    find_social_profiles, 
    social_osint_app,
    get_tiktok_profile,
    get_tiktok_posts_by_hashtag
)
from chimera_intel.core.schemas import (
    SocialOSINTResult, 
    SocialProfile,
    TikTokIntelResult,
    TikTokProfile,
    TikTokPost
)

# Mock the Sherlock result status enum
class MockClaimedStatus:
    name = "CLAIMED"


runner = CliRunner()
TIKTOK_BASE_URL = "https://www.tiktok.com"

# Example HTML response containing __NEXT_DATA__
MOCK_TIKTOK_PROFILE_HTML = """
<html>
<body>
<script id="__NEXT_DATA__" type="application/json">
{
    "props": {
        "pageProps": {
            "userInfo": {
                "user": {
                    "uniqueId": "testuser",
                    "nickname": "Test User",
                    "signature": "This is a test bio.",
                    "followerCount": 100,
                    "followingCount": 50,
                    "heartCount": 1000,
                    "videoCount": 10,
                    "verified": false
                }
            }
        }
    }
}
</script>
</body>
</html>
"""

MOCK_TIKTOK_HASHTAG_HTML = """
<html>
<body>
<script id="__NEXT_DATA__" type="application/json">
{
    "props": {
        "pageProps": {
            "items": [
                {
                    "id": "12345",
                    "desc": "First test post #python",
                    "author": {"uniqueId": "author1"},
                    "stats": {
                        "diggCount": 100,
                        "commentCount": 10,
                        "shareCount": 5,
                        "playCount": 1000
                    }
                },
                {
                    "id": "67890",
                    "desc": "Second test post #python",
                    "author": {"uniqueId": "author2"},
                    "stats": {
                        "diggCount": 200,
                        "commentCount": 20,
                        "shareCount": 15,
                        "playCount": 2000
                    }
                }
            ]
        }
    }
}
</script>
</body>
</html>
"""

class TestSocialOsint(unittest.IsolatedAsyncioTestCase):
    """Test cases for the Social Media OSINT (Sherlock & TikTok) module."""

    # --- Sherlock Function Tests ---

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

    # --- NEW: TikTok Function Tests ---

    @respx.mock
    async def test_get_tiktok_profile_success(self):
        """Tests successful fetching of a TikTok profile."""
        username = "testuser"
        profile_url = f"{TIKTOK_BASE_URL}/@{username}"
        respx.get(profile_url).mock(
            return_value=httpx.Response(200, html=MOCK_TIKTOK_PROFILE_HTML)
        )
        
        # Patch the http_client used in the social_osint module
        with patch("chimera_intel.core.social_osint.http_client", httpx.AsyncClient()) as mock_client:
            mock_client.get = AsyncMock(return_value=httpx.Response(200, html=MOCK_TIKTOK_PROFILE_HTML))
            result = await get_tiktok_profile(username)

        self.assertIsInstance(result, TikTokIntelResult)
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.profile)
        self.assertEqual(result.profile.username, "testuser")
        self.assertEqual(result.profile.nickname, "Test User")
        self.assertEqual(result.profile.follower_count, 100)

    @respx.mock
    async def test_get_tiktok_profile_not_found(self):
        """Tests a 404 response for a TikTok profile."""
        username = "nonexistent"
        profile_url = f"{TIKTOK_BASE_URL}/@{username}"
        
        with patch("chimera_intel.core.social_osint.http_client", httpx.AsyncClient()) as mock_client:
            mock_client.get = AsyncMock(return_value=httpx.Response(404))
            result = await get_tiktok_profile(username)

        self.assertIsInstance(result, TikTokIntelResult)
        self.assertIsNotNone(result.error)
        self.assertIsNone(result.profile)
        self.assertIn("Profile not found", result.error)

    @respx.mock
    async def test_get_tiktok_posts_by_hashtag_success(self):
        """Tests successful fetching of TikTok posts for a hashtag."""
        hashtag = "python"
        tag_url = f"{TIKTOK_BASE_URL}/tag/{hashtag}"
        
        with patch("chimera_intel.core.social_osint.http_client", httpx.AsyncClient()) as mock_client:
            mock_client.get = AsyncMock(return_value=httpx.Response(200, html=MOCK_TIKTOK_HASHTAG_HTML))
            result = await get_tiktok_posts_by_hashtag(hashtag, count=2)

        self.assertIsInstance(result, TikTokIntelResult)
        self.assertIsNone(result.error)
        self.assertIsNone(result.profile)
        self.assertEqual(len(result.posts), 2)
        self.assertEqual(result.posts[0].id, "12345")
        self.assertEqual(result.posts[0].like_count, 100)
        self.assertEqual(result.posts[1].id, "67890")
        self.assertEqual(result.posts[1].comment_count, 20)
        self.assertIn("author2", result.posts[1].video_url)


    # --- CLI Tests ---

    @patch("chimera_intel.core.social_osint.typer.echo")
    @patch("chimera_intel.core.social_osint.save_scan_to_db")
    @patch(
        "chimera_intel.core.social_osint.find_social_profiles", new_callable=AsyncMock
    )
    def test_cli_run_sherlock_success(
        self, mock_find_profiles, mock_save_db, mock_echo
    ):
        """Tests a successful run of the 'social-osint run' (Sherlock) command."""
        mock_data = SocialOSINTResult(
            username="cliuser",
            found_profiles=[
                SocialProfile(name="GitLab", url="https.gitlab.com/cliuser")
            ],
        )
        mock_find_profiles.return_value = mock_data

        # Test the 'run' subcommand
        result = runner.invoke(social_osint_app, ["run", "cliuser"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        mock_find_profiles.assert_called_once_with("cliuser")
        mock_save_db.assert_called_once()
        mock_echo.assert_called_once()
        output = json.loads(mock_echo.call_args[0][0])
        self.assertEqual(output["username"], "cliuser")

    def test_cli_run_sherlock_no_username(self):
        """Tests that the 'run' (Sherlock) command fails if no username is provided."""
        result = runner.invoke(social_osint_app, ["run"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Missing argument 'USERNAME'.", result.stderr)

    # --- NEW: TikTok CLI Tests ---

    @patch("chimera_intel.core.social_osint.typer.echo")
    @patch("chimera_intel.core.social_osint.save_scan_to_db")
    @patch(
        "chimera_intel.core.social_osint.get_tiktok_profile", new_callable=AsyncMock
    )
    def test_cli_run_tiktok_profile_success(
        self, mock_get_profile, mock_save_db, mock_echo
    ):
        """Tests a successful run of the 'social-osint tiktok-profile' command."""
        mock_profile = TikTokProfile(
            uniqueId="cliuser",
            nickname="CLI User",
            signature="Bio",
            followerCount=1, followingCount=2, heartCount=3, videoCount=4, verified=False
        )
        mock_data = TikTokIntelResult(query="cliuser", profile=mock_profile)
        mock_get_profile.return_value = mock_data

        result = runner.invoke(social_osint_app, ["tiktok-profile", "cliuser"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        mock_get_profile.assert_called_once_with("cliuser")
        mock_save_db.assert_called_once()
        mock_echo.assert_called_once()
        output = json.loads(mock_echo.call_args[0][0])
        self.assertEqual(output["query"], "cliuser")
        self.assertEqual(output["profile"]["nickname"], "CLI User")

    @patch("chimera_intel.core.social_osint.typer.echo")
    @patch("chimera_intel.core.social_osint.save_scan_to_db")
    @patch(
        "chimera_intel.core.social_osint.get_tiktok_posts_by_hashtag", new_callable=AsyncMock
    )
    def test_cli_run_tiktok_hashtag_success(
        self, mock_get_hashtag, mock_save_db, mock_echo
    ):
        """Tests a successful run of the 'social-osint tiktok-hashtag' command."""
        mock_post = TikTokPost(
            id="123", description="test", video_url="/",
            diggCount=1, commentCount=1, shareCount=1, playCount=1
        )
        mock_data = TikTokIntelResult(query="python", posts=[mock_post])
        mock_get_hashtag.return_value = mock_data

        result = runner.invoke(social_osint_app, ["tiktok-hashtag", "python", "--count", "5"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        mock_get_hashtag.assert_called_once_with("python", 5)
        mock_save_db.assert_called_once()
        mock_echo.assert_called_once()
        output = json.loads(mock_echo.call_args[0][0])
        self.assertEqual(output["query"], "python")
        self.assertEqual(len(output["posts"]), 1)
        self.assertEqual(output["posts"][0]["id"], "123")


if __name__ == "__main__":
    unittest.main()