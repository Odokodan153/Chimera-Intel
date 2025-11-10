"""
(NEW) Tests for the Active Web Scraper Module.
"""
import unittest
import json
import os
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from pathlib import Path

# Mock 'newspaper' and 'playwright' before importing the module
# This is crucial as they are heavy dependencies.

mock_article = MagicMock()
mock_article.return_value.title = "Test Article"
mock_article.return_value.text = "This is the content."
mock_article.return_value.authors = ["John Doe"]
mock_article.return_value.publish_date = None
mock_article.return_value.top_image = None

mock_playwright = MagicMock()
mock_browser = MagicMock()
mock_page = MagicMock()
mock_playwright.return_value.__enter__.return_value.chromium.launch.return_value = mock_browser
mock_browser.new_page.return_value = mock_page
mock_page.content.return_value = "<html><body><h1>Hello</h1></body></html>"

MOCKS = {
    "newspaper": {"Article": mock_article},
    "playwright.sync_api": {"sync_playwright": mock_playwright}
}

with patch.dict("sys.modules", MOCKS):
    from chimera_intel.core.web_scraper import (
        parse_article_from_url,
        scrape_dynamic_page,
        web_scraper_app
    )
    from chimera_intel.core.schemas import ScrapedArticle

runner = CliRunner()

class TestWebScraper(unittest.TestCase):

    def setUp(self):
        # Reset mocks before each test
        mock_article.reset_mock()
        mock_playwright.reset_mock()
        mock_browser.reset_mock()
        mock_page.reset_mock()

    def test_parse_article_from_url_success(self):
        """Tests parsing a URL with newspaper3k."""
        # Act
        result = parse_article_from_url("http://example.com/article")
        
        # Assert
        self.assertIsNotNone(result)
        self.assertIsInstance(result, ScrapedArticle)
        self.assertEqual(result.title, "Test Article")
        self.assertEqual(result.text_content, "This is the content.")
        
        # Check that download and parse were called
        mock_article.return_value.download.assert_called_once()
        mock_article.return_value.parse.assert_called_once()

    def test_scrape_dynamic_page_success(self):
        """Tests scraping a dynamic page with playwright."""
        # Act
        result = scrape_dynamic_page("http://example.com")
        
        # Assert
        self.assertEqual(result, "<html><body><h1>Hello</h1></body></html>")
        
        # Check that playwright was used correctly
        mock_playwright.assert_called_once()
        mock_browser.new_page.assert_called_once()
        mock_page.goto.assert_called_once_with("http://example.com", wait_until="networkidle")
        mock_page.wait_for_selector.assert_not_called() # No selector was passed
        mock_browser.close.assert_called_once()

    def test_scrape_dynamic_page_with_wait(self):
        """Tests scraping a dynamic page with a wait selector."""
        # Act
        result = scrape_dynamic_page("http://example.com", wait_for_selector="#data")
        
        # Assert
        self.assertEqual(result, "<html><body><h1>Hello</h1></body></html>")
        mock_page.goto.assert_called_once_with("http://example.com", wait_until="networkidle")
        # Check that it waited for the selector
        mock_page.wait_for_selector.assert_called_once_with("#data")

    @patch("chimera_intel.core.web_scraper.parse_article_from_url")
    def test_cli_parse_article(self, mock_parse):
        """Tests the parse-article CLI command."""
        # Arrange
        mock_parse.return_value = ScrapedArticle(
            url="http://fake.com",
            title="Fake Title",
            text_content="Fake content",
        )
        
        with runner.isolated_filesystem():
            # Act
            result = runner.invoke(
                web_scraper_app,
                ["parse-article", "http://fake.com", "-o", "article.json"]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Article Parsed Successfully", result.stdout)
            self.assertIn("Data saved to article.json", result.stdout)
            
            # Check the file content
            self.assertTrue(Path("article.json").exists())
            with open("article.json", 'r') as f:
                data = json.load(f)
            self.assertEqual(data['title'], "Fake Title")

    @patch("chimera_intel.core.web_scraper.scrape_dynamic_page")
    def test_cli_scrape_dynamic(self, mock_scrape):
        """Tests the scrape-dynamic CLI command."""
        # Arrange
        mock_scrape.return_value = "<html><head></head></html>"
        
        with runner.isolated_filesystem():
            # Act
            result = runner.invoke(
                web_scraper_app,
                ["scrape-dynamic", "http://fake.com", "-o", "page.html"]
            )
            
            # Assert
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Full HTML content saved to page.html", result.stdout)
            
            # Check the file content
            self.assertTrue(Path("page.html").exists())
            with open("page.html", 'r') as f:
                data = f.read()
            self.assertEqual(data, "<html><head></head></html>")