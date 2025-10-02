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
    """Test cases for the social_media_monitor module."""

    @patch("chimera_intel.core.social_media_monitor.TwitterStreamListener")
    def test_monitor_twitter_stream_success(self, mock_stream_listener):
        """Tests a successful real-time monitoring session."""
        mock_stream_instance = mock_stream_listener.return_value
        mock_stream_instance.tweets = [
            Tweet(id="123", text="Test tweet", author_id="456", created_at="")
        ]

        with patch(
            "chimera_intel.core.social_media_monitor.API_KEYS.twitter_bearer_token",
            "fake_token",
        ):
            result = monitor_twitter_stream(["test"], limit=1)
        self.assertIsInstance(result, TwitterMonitoringResult)
        self.assertEqual(result.total_tweets_found, 1)

    @patch("chimera_intel.core.social_media_monitor.build")
    def test_monitor_youtube_success(self, mock_build):
        """Tests a successful YouTube monitoring session."""
        mock_youtube_service = MagicMock()
        mock_youtube_service.search().list().execute.return_value = {
            "items": [
                {
                    "id": {"videoId": "test_id"},
                    "snippet": {
                        "title": "Test Video",
                        "channelId": "channel_id",
                        "channelTitle": "Test Channel",
                        "publishedAt": "2025-01-01T00:00:00Z",
                    },
                }
            ]
        }
        mock_build.return_value = mock_youtube_service

        with patch(
            "chimera_intel.core.social_media_monitor.API_KEYS.youtube_api_key",
            "fake_youtube_key",
        ):
            result = monitor_youtube("test query", limit=1)
        self.assertIsInstance(result, YouTubeMonitoringResult)
        self.assertEqual(result.total_videos_found, 1)

    @patch("chimera_intel.core.social_media_monitor.monitor_twitter_stream")
    def test_cli_twitter_monitoring(self, mock_monitor):
        """Tests the twitter monitoring CLI command."""
        mock_monitor.return_value.model_dump.return_value = {}
        result = runner.invoke(social_media_app, ["twitter", "chimera"])
        self.assertEqual(result.exit_code, 0)
        mock_monitor.assert_called_with(["chimera"], 10)

    @patch("chimera_intel.core.social_media_monitor.monitor_youtube")
    def test_cli_youtube_monitoring(self, mock_monitor):
        """Tests the youtube monitoring CLI command."""
        mock_monitor.return_value.model_dump.return_value = {}
        result = runner.invoke(social_media_app, ["youtube", "chimera"])
        self.assertEqual(result.exit_code, 0)
        mock_monitor.assert_called_with("chimera", 10)


if __name__ == "__main__":
    unittest.main()
