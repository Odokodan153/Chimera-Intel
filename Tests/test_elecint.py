import unittest
from unittest.mock import patch, Mock
from src.chimera_intel.core.elecint import ElecInt


class TestElecInt(unittest.TestCase):
    def setUp(self):
        self.elecint = ElecInt()

    @patch("requests.get")
    def test_get_campaign_donations(self, mock_get):
        # Mock the FEC API response

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "contributor_name": "Doe, John",
                    "contribution_receipt_amount": 100.00,
                    "contribution_receipt_date": "2023-01-01",
                }
            ]
        }
        mock_get.return_value = mock_response

        # Set a dummy API key for the test

        self.elecint.fec_api_key = "fake_key"
        donations = self.elecint.get_campaign_donations("C00431445")
        self.assertEqual(len(donations), 1)
        self.assertEqual(donations[0]["contributor_name"], "Doe, John")

    @patch("tweepy.Client")
    def test_analyze_sentiment_drift(self, mock_tweepy_client):
        # Mock the Tweepy client

        mock_tweet = Mock()
        mock_tweet.text = "This is a great political message."
        mock_response = Mock()
        mock_response.data = [mock_tweet]
        mock_tweepy_client.return_value.search_recent_tweets.return_value = (
            mock_response
        )

        self.elecint.twitter_client = mock_tweepy_client()
        result = self.elecint.analyze_sentiment_drift("politics")
        self.assertEqual(result["tweets_analyzed"], 1)
        self.assertTrue(float(result["average_sentiment_polarity"]) > 0)

    @patch("tweepy.Client")
    def test_trace_disinformation_source(self, mock_tweepy_client):
        # Mock Tweepy to simulate a retweet network

        mock_tweet1 = Mock(author_id="101", in_reply_to_user_id="202")
        mock_tweet2 = Mock(author_id="102", in_reply_to_user_id="202")
        mock_response = Mock()
        mock_response.data = [mock_tweet1, mock_tweet2]
        mock_tweepy_client.return_value.search_recent_tweets.return_value = (
            mock_response
        )

        self.elecint.twitter_client = mock_tweepy_client()
        result = self.elecint.trace_disinformation_source("fake news")
        self.assertEqual(result["retweets_analyzed"], 2)
        self.assertIn("User ID 202", result["top_amplifiers_by_centrality"])


if __name__ == "__main__":
    unittest.main()
