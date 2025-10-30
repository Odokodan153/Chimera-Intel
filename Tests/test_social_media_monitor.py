import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from chimera_intel.core.social_media_monitor import (
    monitor_twitter_stream,
    monitor_youtube,
    social_media_app,
)
from chimera_intel.core.schemas import (
    TwitterMonitoringResult,
    YouTubeMonitoringResult,
    Tweet,
)

runner = CliRunner()


class TestSocialMediaMonitor(unittest.TestCase):
    """Test cases for the real-time Social Media Monitoring module."""

    # --- Twitter Monitoring Tests ---

    @patch("chimera_intel.core.social_media_monitor.TwitterStreamListener")
    @patch("chimera_intel.core.social_media_monitor.API_KEYS")
    def test_monitor_twitter_stream_success(self, mock_api_keys, mock_stream_listener):
        """Tests a successful Twitter stream monitoring session."""
        # Arrange

        mock_api_keys.twitter_bearer_token = "fake_bearer_token"
        mock_stream_instance = mock_stream_listener.return_value
        mock_stream_instance.tweets = [
            Tweet(id="123", text="Test tweet", author_id="456", created_at="")
        ]
        # Mock the get_rules to return an empty list initially

        mock_stream_instance.get_rules.return_value = MagicMock(data=[])

        # Act

        result = monitor_twitter_stream(["test"], limit=1)

        # Assert

        self.assertIsInstance(result, TwitterMonitoringResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_tweets_found, 1)
        self.assertEqual(result.tweets[0].text, "Test tweet")
        mock_stream_instance.filter.assert_called_once()

    def test_monitor_twitter_stream_no_api_key(self):
        """Tests Twitter monitoring when the API key is missing."""
        with patch(
            "chimera_intel.core.social_media_monitor.API_KEYS.twitter_bearer_token",
            None,
        ):
            result = monitor_twitter_stream(["test"], limit=1)
            self.assertIsNotNone(result.error)
            self.assertIn("Twitter Bearer Token not found", result.error)

    # --- YouTube Monitoring Tests ---

    @patch("chimera_intel.core.social_media_monitor.build")
    @patch("chimera_intel.core.social_media_monitor.API_KEYS")
    def test_monitor_youtube_success(self, mock_api_keys, mock_build):
        """Tests a successful YouTube monitoring session."""
        # Arrange

        mock_api_keys.youtube_api_key = "fake_yt_key"
        mock_youtube_service = MagicMock()
        mock_search_list = MagicMock()
        mock_search_list.execute.return_value = {
            "items": [
                {
                    "id": {"videoId": "xyz"},
                    "snippet": {
                        "title": "Test Video",
                        "channelId": "123",
                        "channelTitle": "Test Channel",
                        "publishedAt": "2023-01-01T00:00:00Z",
                    },
                }
            ]
        }
        mock_youtube_service.search.return_value.list.return_value = mock_search_list
        mock_build.return_value = mock_youtube_service

        # Act

        result = monitor_youtube("test query", limit=1)

        # Assert

        self.assertIsInstance(result, YouTubeMonitoringResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.total_videos_found, 1)
        self.assertEqual(result.videos[0].title, "Test Video")

    # --- CLI Tests ---

    @patch("chimera_intel.core.social_media_monitor.monitor_twitter_stream")
    def test_cli_twitter_monitor_success(self, mock_monitor):
        """Tests the 'social-media twitter' CLI command."""
        # Arrange

        mock_monitor.return_value = TwitterMonitoringResult(
            query="chimera", total_tweets_found=1
        )

        # Act

        result = runner.invoke(social_media_app, ["twitter", "chimera", "--limit", "1"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_monitor.assert_called_with(["chimera"], 1)
        self.assertIn('"total_tweets_found": 1', result.stdout)

    @patch("chimera_intel.core.social_media_monitor.monitor_youtube")
    def test_cli_youtube_monitor_success(self, mock_monitor):
        """Tests the 'social-media youtube' CLI command."""
        # Arrange

        mock_monitor.return_value = YouTubeMonitoringResult(
            query="intel", total_videos_found=1
        )

        # Act

        result = runner.invoke(social_media_app, ["youtube", "intel", "--limit", "1"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_monitor.assert_called_with("intel", 1)
        self.assertIn('"total_videos_found": 1', result.stdout)


if __name__ == "__main__":
    unittest.main()
