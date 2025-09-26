import unittest
from unittest.mock import patch, MagicMock
import tweepy
from chimera_intel.core.social_media_monitor import (
    monitor_twitter_stream,
    monitor_youtube,
    TwitterStreamListener,
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

        # We need to capture the listener instance to call its on_tweet method

        listener_instance = []

        def mock_init(bearer_token, limit=10):
            # The actual listener is instantiated inside the function we're testing.
            # We'll create a real one here to capture it.

            real_listener = TwitterStreamListener(bearer_token, limit=limit)
            listener_instance.append(real_listener)
            # We still return the main mock instance for other calls like filter, get_rules etc.

            return mock_stream_instance

        mock_streaming_client.side_effect = mock_init

        def mock_filter(*args, **kwargs):
            # Now we have the listener instance, we can call its methods

            if listener_instance:
                tweet = tweepy.Tweet(
                    data={
                        "id": "12345",
                        "text": "This is a test tweet",
                        "author_id": "67890",
                        "created_at": "2025-09-13T00:00:00Z",
                    }
                )
                listener_instance[0].on_tweet(tweet)
                # This will stop the stream after one tweet, as intended

                listener_instance[0].disconnect()

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
