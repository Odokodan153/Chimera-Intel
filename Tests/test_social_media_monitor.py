import unittest
from unittest.mock import patch, MagicMock
from chimera_intel.core.social_media_monitor import (
    monitor_twitter_stream,
    ChimeraTweetStream,
)
from chimera_intel.core.schemas import RealTimeMonitoringResult, Tweet


class TestSocialMediaMonitor(unittest.TestCase):
    """Test cases for the social_media_monitor module."""

    @patch("chimera_intel.core.social_media_monitor.tweepy.StreamingClient")
    def test_monitor_twitter_stream_success(self, mock_streaming_client):
        """Tests a successful real-time monitoring session."""
        # Arrange

        mock_stream_instance = mock_streaming_client.return_value
        mock_stream_instance.get_rules.return_value.data = []

        # Simulate the on_tweet callback being called

        def mock_filter():
            tweet = MagicMock()
            tweet.id = 12345
            tweet.text = "This is a test tweet"
            tweet.author_id = 67890
            tweet.created_at = "2025-09-13T00:00:00Z"
            mock_stream_instance.on_tweet(tweet)

        mock_stream_instance.filter.side_effect = mock_filter

        # Act

        with patch(
            "chimera_intel.core.social_media_monitor.API_KEYS.twitter_bearer_token",
            "fake_token",
        ):
            result = monitor_twitter_stream(["test"], limit=1)
        # Assert

        self.assertIsInstance(result, RealTimeMonitoringResult)
        self.assertEqual(result.total_tweets_found, 1)
        self.assertEqual(len(result.tweets), 1)
        self.assertEqual(result.tweets[0].text, "This is a test tweet")
        self.assertIsNone(result.error)

    def test_monitor_twitter_stream_no_api_key(self):
        """Tests that the function returns an error if no API key is provided."""
        # Act

        with patch(
            "chimera_intel.core.social_media_monitor.API_KEYS.twitter_bearer_token",
            None,
        ):
            result = monitor_twitter_stream(["test"], limit=1)
        # Assert

        self.assertIsNotNone(result.error)
        self.assertIn("Twitter Bearer Token not found", result.error)


if __name__ == "__main__":
    unittest.main()
