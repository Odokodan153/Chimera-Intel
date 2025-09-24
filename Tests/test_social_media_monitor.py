import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.social_media_monitor import (
    monitor_twitter_stream,
    monitor_youtube,
)
from chimera_intel.core.schemas import TwitterMonitoringResult, YouTubeMonitoringResult


class TestSocialMediaMonitor(unittest.TestCase):
    """Test cases for the social_media_monitor module."""

    @patch("chimera_intel.core.social_media_monitor.tweepy.StreamingClient")
    def test_monitor_twitter_stream_success(self, mock_streaming_client):
        """Tests a successful real-time monitoring session."""
        mock_stream_instance = mock_streaming_client.return_value
        mock_rules_response = MagicMock()
        mock_rules_response.data = []
        mock_stream_instance.get_rules.return_value = mock_rules_response

        def mock_filter(*args, **kwargs):
            tweet = MagicMock()
            tweet.id = 12345
            tweet.text = "This is a test tweet"
            tweet.author_id = 67890
            tweet.created_at = "2025-09-13T00:00:00Z"
            mock_stream_instance.on_tweet(tweet)

        mock_stream_instance.filter.side_effect = mock_filter

        with patch(
            "chimera_intel.core.social_media_monitor.API_KEYS.twitter_bearer_token",
            "fake_token",
        ):
            result = monitor_twitter_stream(["test"], limit=1)

        self.assertIsInstance(result, TwitterMonitoringResult)
        self.assertEqual(result.total_tweets_found, 1)
        self.assertEqual(result.tweets[0].text, "This is a test tweet")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.social_media_monitor.build")
    def test_monitor_youtube_success(self, mock_build):
        """Tests a successful YouTube monitoring session."""
        mock_youtube_service = MagicMock()
        mock_search_list = MagicMock()
        mock_search_list.execute.return_value = {
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
        mock_youtube_service.search.return_value.list.return_value = mock_search_list
        mock_build.return_value = mock_youtube_service

        with patch(
            "chimera_intel.core.social_media_monitor.API_KEYS.youtube_api_key",
            "fake_youtube_key",
        ):
            result = monitor_youtube("test query", limit=1)

        self.assertIsInstance(result, YouTubeMonitoringResult)
        self.assertEqual(result.total_videos_found, 1)
        self.assertEqual(result.videos[0].title, "Test Video")
        self.assertIsNone(result.error)


if __name__ == "__main__":
    unittest.main()