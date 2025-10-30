import unittest
from unittest.mock import patch
from typer.testing import CliRunner
import sys
import os

# FIX: Add the project's src directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

# FIX: Remove 'src.' prefix as 'src' is now on the path
from chimera_intel.core.ainews import AiNews, app

# Use CliRunner for Typer app testing
runner = CliRunner()


class TestAiNews(unittest.TestCase):
    def setUp(self):
        self.ainews = AiNews()
        self.runner = CliRunner()

    def test_get_latest_ai_news_live(self):
        """
        Tests the live fetching and parsing of the AI news feed.
        (Original Test)
        """
        articles = self.ainews.get_latest_ai_news(limit=5)

        # Check that the function returns a list
        self.assertIsInstance(articles, list)

        # If articles are found, check the structure of the first one
        if articles:
            self.assertIn("title", articles[0])
            self.assertIn("author", articles[0])
            self.assertIn("published", articles[0])
            self.assertIn("link", articles[0])

    # --- Extended Test ---
    # FIX: Update patch path
    @patch("chimera_intel.core.ainews.feedparser.parse")
    def test_get_latest_ai_news_exception(self, mock_parse):
        """
        Tests the exception handling in get_latest_ai_news.
        This covers the 'except Exception as e' block.
        """
        # Arrange
        mock_parse.side_effect = ConnectionError("Failed to connect")

        # Act
        articles = self.ainews.get_latest_ai_news(limit=5)

        # Assert
        self.assertIsInstance(articles, list)
        self.assertEqual(len(articles), 0)

    # --- Extended Test ---
    # FIX: Update patch path
    @patch("chimera_intel.core.ainews.AiNews.get_latest_ai_news")
    def test_cli_latest_news_success(self, mock_get_news):
        """
        Tests the 'latest' CLI command in a successful scenario.
        This covers the main execution path of the CLI.
        """
        # Arrange
        mock_article = {
            "title": "Test AI Article",
            "author": "Test Author",
            "published": "2023-01-01T12:00:00Z",
            "link": "http://example.com",
        }
        mock_get_news.return_value = [mock_article]

        # Act
        # --- FIX: Removed "latest" from the invoke call ---
        result = self.runner.invoke(app, ["--limit", "1"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Test AI Article", result.stdout)
        self.assertIn("Test Author", result.stdout)
        self.assertIn("2023-01-01", result.stdout)
        mock_get_news.assert_called_with(1)

    # --- Extended Test ---
    # FIX: Update patch path
    @patch("chimera_intel.core.ainews.AiNews.get_latest_ai_news")
    def test_cli_latest_news_no_articles(self, mock_get_news):
        """
        Tests the 'latest' CLI command when no articles are found.
        This covers the 'if not articles:' block.
        """
        # Arrange
        mock_get_news.return_value = []

        # Act
        # --- FIX: Removed "latest" from the invoke call ---
        result = self.runner.invoke(app, [])

        # Assert
        self.assertEqual(result.exit_code, 0)
        self.assertIn("No recent AI articles found", result.stdout)


if __name__ == "__main__":
    unittest.main()
