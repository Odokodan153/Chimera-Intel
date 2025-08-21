import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError
from typer.testing import CliRunner

from chimera_intel.cli import app
from chimera_intel.core.social_analyzer import discover_rss_feed, analyze_feed_content
from chimera_intel.core.schemas import (
    SocialContentAnalysis,
    AnalyzedPost,
)

runner = CliRunner()


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
        """Tests the case where no RSS feed can be discovered due to network errors."""
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

        # FIX: Provide a realistic entry object with an actual string for the summary

        mock_entry = MagicMock()
        mock_entry.get.side_effect = lambda key, default: {
            "title": "Test Post",
            "link": "#",
        }.get(key, default)
        # Make summary a real string that BeautifulSoup can process

        mock_entry.summary = "This is the summary content."
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

    # CLI Tests

    @patch("chimera_intel.core.social_analyzer.discover_rss_feed")
    @patch("chimera_intel.core.social_analyzer.analyze_feed_content")
    def test_cli_social_run_success(self, mock_analyze, mock_discover):
        """Tests a successful 'social run' CLI command."""
        mock_discover.return_value = "http://fake.url/feed.xml"
        mock_analyze.return_value = SocialContentAnalysis(
            feed_title="Test Feed",
            posts=[
                AnalyzedPost(
                    title="Test Post",
                    link="#",
                    top_category="Product Launch",
                    confidence="99.00%",
                )
            ],
        )

        result = runner.invoke(app, ["scan", "social", "run", "example.com"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"feed_title": "Test Feed"', result.stdout)

    def test_cli_social_run_invalid_domain(self):
        """Tests the 'social run' command with an invalid domain."""
        result = runner.invoke(app, ["scan", "social", "run", "invalid-domain"])
        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.social_analyzer.discover_rss_feed")
    def test_cli_social_run_no_feed(self, mock_discover):
        """Tests the 'social run' command when no RSS feed is found."""
        mock_discover.return_value = None
        result = runner.invoke(app, ["scan", "social", "run", "example.com"])
        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
