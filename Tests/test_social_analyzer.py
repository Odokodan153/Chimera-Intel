import unittest
from unittest.mock import patch, MagicMock
from httpx import Response, RequestError
from typer.testing import CliRunner

# Import the specific Typer app for this module, not the main one


from chimera_intel.core.social_analyzer import social_app
from chimera_intel.core.social_analyzer import (
    discover_rss_feed,
    analyze_feed_content,
)
from chimera_intel.core.schemas import (
    SocialContentAnalysis,
    AnalyzedPost,
    ProjectConfig,
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
    @patch("chimera_intel.core.social_analyzer.classify_text_zero_shot")
    def test_analyze_feed_content_success(self, mock_classify, mock_feedparser):
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

        mock_classify.return_value = {"labels": ["Product Launch"], "scores": [0.99]}

        result = analyze_feed_content("http://fake.url/feed.xml")
        self.assertEqual(result.feed_title, "Test Feed Title")
        self.assertEqual(len(result.posts), 1)
        self.assertEqual(result.posts[0].top_category, "Product Launch")
        self.assertIsNone(result.error)

    @patch("chimera_intel.core.social_analyzer.feedparser")
    @patch("chimera_intel.core.social_analyzer.classify_text_zero_shot")
    def test_analyze_feed_content_no_classifier(self, mock_classify, mock_feedparser):
        """Tests feed analysis when the AI classifier (transformers) is not installed."""
        # Arrange

        mock_classify.return_value = None  # Simulate the classifier not being available

        mock_feed = MagicMock()
        mock_feed.bozo = 0
        mock_feed.feed.get.return_value = "Test Feed Title"
        mock_entry = MagicMock()
        mock_entry.summary = "This is the summary content."
        mock_feed.entries = [mock_entry]
        mock_feedparser.parse.return_value = mock_feed

        # Act

        result = analyze_feed_content("http://fake.url/feed.xml")

        # Assert

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.error)
        self.assertIn("AI analysis skipped", result.error)

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
        """Tests a successful 'social run' CLI command with an explicit domain."""
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

        result = runner.invoke(social_app, ["example.com"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn('"feed_title": "Test Feed"', result.stdout)
        # Ensure the discover function was called with the explicit domain

        mock_discover.assert_called_with("example.com")

    def test_cli_social_run_invalid_domain(self):
        """Tests the 'social run' command with an invalid domain."""
        result = runner.invoke(social_app, ["invalid-domain"])
        self.assertEqual(result.exit_code, 1)

    @patch("chimera_intel.core.social_analyzer.discover_rss_feed")
    def test_cli_social_run_no_feed(self, mock_discover):
        """Tests the 'social run' command when no RSS feed is found."""
        mock_discover.return_value = None
        result = runner.invoke(social_app, ["example.com"])
        self.assertEqual(result.exit_code, 1)

    # --- NEW: Project-Aware CLI Tests ---

    @patch("chimera_intel.core.project_manager.get_active_project")
    @patch("chimera_intel.core.social_analyzer.discover_rss_feed")
    @patch("chimera_intel.core.social_analyzer.analyze_feed_content")
    def test_cli_social_run_with_active_project(
        self, mock_analyze, mock_discover, mock_get_project
    ):
        """Tests the CLI command using an active project's context when no domain is provided."""
        # Arrange: Mock the active project and the downstream functions

        mock_project = ProjectConfig(
            project_name="TestProject",
            created_at="2025-01-01",
            domain="project-domain.com",
        )
        mock_get_project.return_value = mock_project
        mock_discover.return_value = "http://fake.url/feed.xml"
        mock_analyze.return_value = SocialContentAnalysis(
            feed_title="Project Feed", posts=[]
        )

        # Act: Run the command without an explicit domain

        result = runner.invoke(social_app, [])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Using domain 'project-domain.com' from active project", result.stdout
        )
        self.assertIn('"feed_title": "Project Feed"', result.stdout)
        # Verify that the discover function was called with the domain from the project

        mock_discover.assert_called_with("project-domain.com")

    @patch("chimera_intel.core.project_manager.get_active_project")
    def test_cli_social_run_no_domain_no_project(self, mock_get_project):
        """Tests the CLI command fails when no domain is provided and no active project is set."""
        # Arrange: Mock that there is no active project

        mock_get_project.return_value = None

        # Act: Run the command without a domain

        result = runner.invoke(social_app, [])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No target provided and no active project set", result.stdout)


if __name__ == "__main__":
    unittest.main()
