from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import requests  # Import requests to patch its exceptions

# --- FIX: Ensure imports point to the correct module paths ---
from chimera_intel.core.hackernews import HackerNews, app as hackernews_app

runner = CliRunner()


# --- Mocks for API responses ---
MOCK_TOP_STORIES_IDS = [123, 456]
MOCK_STORY_123 = {
    "title": "Mock Story 1",
    "by": "author1",
    "time": 1678886400,
    "url": "http://example.com/1"
}
MOCK_STORY_456 = {
    "title": "Mock Story 2",
    "by": "author2",
    "time": 1678886500,
    "url": "http://example.com/2"
}

# This test now uses pytest style instead of unittest
def test_get_top_stories_live():
    """
    Tests the live fetching and parsing of the Hacker News feed.
    (This is the original test, kept as a live integration test)
    """
    hackernews = HackerNews()
    articles = hackernews.get_top_stories(limit=3)

    assert isinstance(articles, list)
    assert len(articles) <= 3

    if articles:
        assert "title" in articles[0]
        assert "author" in articles[0]
        assert "published" in articles[0]
        assert "link" in articles[0]


# --- NEW TEST: Mock the logic for 'get_top_stories' ---
@patch("chimera_intel.core.hackernews.requests.get")
def test_get_top_stories_mocked_success(mock_get):
    """Tests the get_top_stories logic with a mocked successful API response."""
    
    # Define mock responses for each URL
    def mock_requests_get(url):
        mock_resp = MagicMock()
        if "topstories.json" in url:
            mock_resp.json.return_value = MOCK_TOP_STORIES_IDS
        elif "item/123.json" in url:
            mock_resp.json.return_value = MOCK_STORY_123
        elif "item/456.json" in url:
            mock_resp.json.return_value = MOCK_STORY_456
        else:
            mock_resp.status_code = 404
        return mock_resp

    mock_get.side_effect = mock_requests_get
    
    hackernews = HackerNews()
    articles = hackernews.get_top_stories(limit=2)

    assert len(articles) == 2
    assert articles[0]["title"] == "Mock Story 1"
    assert articles[1]["author"] == "author2"
    assert articles[1]["link"] == "http://example.com/2"


# --- NEW TEST: Mock the logic for 'get_top_stories' during an API failure ---
@patch("chimera_intel.core.hackernews.requests.get")
def test_get_top_stories_api_exception(mock_get, capsys):
    """Tests the get_top_stories logic when the API raises an exception."""
    
    mock_get.side_effect = requests.exceptions.RequestException("API is down")
    
    hackernews = HackerNews()
    articles = hackernews.get_top_stories()
    
    captured = capsys.readouterr()

    assert articles == []
    assert "Error fetching Hacker News feed: API is down" in captured.out


# --- NEW TEST: Test the CLI 'top' command successfully ---
@patch("chimera_intel.core.hackernews.HackerNews.get_top_stories")
def test_cli_top_stories_success(mock_get_stories):
    """Tests the 'top' CLI command on a successful run."""
    
    # Mock the logic function to return predictable data
    mock_get_stories.return_value = [
        {
            "title": "Test Title",
            "author": "Test Author",
            "published": 12345678,
            "link": "http://test.com"
        }
    ]
    
    result = runner.invoke(hackernews_app, ["top", "--limit", "1"])
    
    assert result.exit_code == 0
    assert "Top Stories from Hacker News" in result.stdout
    assert "Test Title" in result.stdout
    assert "Test Author" in result.stdout
    # Check that the limit was respected by the mocked call
    mock_get_stories.assert_called_with(limit=1)


# --- NEW TEST: Test the CLI 'top' command when no articles are found ---
@patch("chimera_intel.core.hackernews.HackerNews.get_top_stories")
def test_cli_top_stories_no_articles(mock_get_stories):
    """Tests the 'top' CLI command when the logic returns no articles."""
    
    mock_get_stories.return_value = []
    
    result = runner.invoke(hackernews_app, ["top"])
    
    assert result.exit_code == 0
    assert "No recent articles found in the feed" in result.stdout


# --- NEW TEST: Test the CLI default behavior (no args) ---
def test_cli_no_args():
    """Tests that invoking the app with no commands prints the help message."""
    result = runner.invoke(hackernews_app, [])
    
    assert result.exit_code == 0
    # 'no_args_is_help=True' means it should print help
    assert "Usage: " in result.stdout
    assert "Hacker News (HackerNews) tools." in result.stdout

def test_get_top_stories(self):
        """
        Tests the live fetching and parsing of the Hacker News feed.
        """
        articles = self.hackernews.get_top_stories(limit=5)

        # Check that the function returns a list

        self.assertIsInstance(articles, list)

        # If articles are found, check the structure of the first one

        if articles:
            self.assertIn("title", articles[0])
            self.assertIn("author", articles[0])
            self.assertIn("published", articles[0])
            self.assertIn("link", articles[0])