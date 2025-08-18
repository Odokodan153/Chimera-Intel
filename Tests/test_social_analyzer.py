import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError
from chimera_intel.core.social_analyzer import discover_rss_feed, analyze_feed_content


class TestSocialAnalyzer(unittest.TestCase):
    """Test cases for the social analyzer module."""

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_discover_rss_feed_from_html(self, mock_get):
        """Tests discovering an RSS feed from the homepage's <link> tag."""
        mock_html = '<html><head><link type="application/rss+xml" href="/blog/feed.xml"></head></html>'
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = mock_html
        mock_get.return_value = mock_response

        feed_url = discover_rss_feed("example.com")
        self.assertEqual(feed_url, "https://www.example.com/blog/feed.xml")

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_discover_rss_feed_from_sitemap(self, mock_get):
        """Tests discovering an RSS feed from the sitemap.xml file."""
        mock_sitemap_xml = (
            "<urlset><url><loc>https://example.com/main-rss-feed</loc></url></urlset>"
        )
        # First call (homepage) fails, second call (sitemap) succeeds

        mock_fail_response = MagicMock(spec=Response, status_code=404)
        mock_success_response = MagicMock(
            spec=Response, status_code=200, content=mock_sitemap_xml.encode("utf-8")
        )
        mock_get.side_effect = [mock_fail_response, mock_success_response]

        feed_url = discover_rss_feed("example.com")
        self.assertEqual(feed_url, "https://example.com/main-rss-feed")

    @patch("chimera_intel.core.http_client.sync_client.get")
    def test_discover_rss_feed_not_found(self, mock_get):
        """Tests the case where no RSS feed can be discovered."""
        mock_get.side_effect = RequestError("Network error")
        feed_url = discover_rss_feed("example.com")
        self.assertIsNone(feed_url)

    @patch("chimera_intel.core.social_analyzer.feedparser")
    @patch("chimera_intel.core.social_analyzer.classifier")
    def test_analyze_feed_content_success(self, mock_classifier, mock_feedparser):
        """Tests a successful analysis of a feed."""
        mock_feed = MagicMock()
        mock_feed.bozo = 0
        mock_feed.feed.get.return_value = "Test Feed Title"
        mock_entry = MagicMock()
        mock_entry.get.side_effect = lambda key, default: {
            "title": "Test Post",
            "summary": "Some content",
            "link": "#",
        }.get(key, default)
        mock_feed.entries = [mock_entry]
        mock_feedparser.parse.return_value = mock_feed

        mock_classifier.return_value = {"labels": ["Product Launch"], "scores": [0.99]}

        result = analyze_feed_content("http://fake.url/feed.xml")
        self.assertEqual(result.feed_title, "Test Feed Title")
        self.assertEqual(len(result.posts), 1)
        self.assertEqual(result.posts[0].top_category, "Product Launch")
        self.assertIsNone(result.error)

    def test_analyze_feed_content_no_classifier(self):
        """Tests feed analysis when the AI classifier (transformers) is not installed."""
        with patch("chimera_intel.core.social_analyzer.classifier", None):
            result = analyze_feed_content("http://fake.url/feed.xml")
            self.assertIsNotNone(result.error)
            self.assertIn("not installed", result.error)

    @patch("chimera_intel.core.social_analyzer.feedparser")
    def test_analyze_feed_content_parse_error(self, mock_feedparser):
        """Tests feed analysis when feedparser encounters a critical error."""
        mock_feedparser.parse.side_effect = Exception("Malformed XML")

        result = analyze_feed_content("http://fake.url/feed.xml")
        self.assertIsNotNone(result.error)
        self.assertIn("Malformed XML", result.error)


if __name__ == "__main__":
    unittest.main()
