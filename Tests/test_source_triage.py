import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from typer.testing import CliRunner
from chimera_intel.core.source_triage import triage_app, get_source_triage
from playwright.sync_api import Error as PlaywrightError

runner = CliRunner()

@pytest.fixture
def mock_whois():
    """Fixture to mock the whois.query method."""
    mock_info = MagicMock()
    mock_info.creation_date = datetime.now() - timedelta(days=500)
    with patch("chimera_intel.core.source_triage.whois.query", return_value=mock_info) as mock:
        yield mock

@pytest.fixture
def mock_whois_new():
    """Fixture to mock a new domain."""
    mock_info = MagicMock()
    mock_info.creation_date = datetime.now() - timedelta(days=30)
    with patch("chimera_intel.core.source_triage.whois.query", return_value=mock_info) as mock:
        yield mock

@pytest.fixture
def mock_playwright():
    """Fixture to mock the sync_playwright API."""
    with patch("chimera_intel.core.source_triage.sync_playwright") as mock_sync:
        mock_playwright = mock_sync.return_value.__enter__.return_value
        mock_browser = mock_playwright.chromium.launch.return_value
        mock_context = mock_browser.new_context.return_value
        mock_page = mock_context.new_page.return_value

        # Set default mock page content
        mock_page.title.return_value = "Test Page Title"
        mock_page.content.return_value = "<html><head><title>Test Page Title</title></head><body>Hello world</body></html>"
        
        # Make the mock page available to tests
        yield mock_page 

def test_get_source_triage_domain_age(mock_whois, mock_playwright):
    """Test successful domain age check and basic scraping."""
    url = "http://example.com"
    result = get_source_triage(url)

    assert result.error is None
    assert result.domain == "example.com"
    assert result.domain_age_days == 500
    assert "Test Page Title" in result.page_title
    assert not result.is_social_media

def test_get_source_triage_new_domain(mock_whois_new, mock_playwright):
    """Test that a new domain triggers an indicator."""
    url = "http://new-site.com"
    result = get_source_triage(url)

    assert result.domain_age_days == 30
    assert len(result.indicators) > 0
    assert "Domain is very new (30 days old)" in result.indicators

def test_get_source_triage_social_twitter(mock_whois, mock_playwright):
    """Test Twitter social media heuristics on rendered HTML."""
    # Update mock page content for this specific test
    mock_playwright.title.return_value = "User Profile (@user) / X"
    mock_playwright.content.return_value = "<html><body>Some dynamic text... Joined May 2020 ... 1,234 Followers</body></html>"
    
    url = "https://twitter.com/user"
    result = get_source_triage(url)

    assert result.is_social_media
    assert result.domain == "twitter.com"
    assert result.profile_details.get("Joined") == "May 2020"
    assert "Page contains 'followers' keyword." in result.indicators

def test_cli_run_source_triage(mock_whois, mock_playwright):
    """Test the CLI command."""
    result = runner.invoke(triage_app, ["run", "http://example.com"])
    assert result.exit_code == 0
    assert '"domain": "example.com"' in result.stdout
    assert '"domain_age_days": 500' in result.stdout

def test_get_source_triage_playwright_fail(mock_whois):
    """Test failure of Playwright scraping."""
    with patch("chimera_intel.core.source_triage.sync_playwright") as mock_sync:
        mock_sync.return_value.__enter__.return_value.chromium.launch.side_effect = PlaywrightError("Browser failed")
        
        result = get_source_triage("http://example.com")
        
        assert "Failed to scrape URL with Playwright" in result.error
        assert result.page_title is None
        assert "Dynamic page scraping failed" in result.indicators

def test_get_source_triage_www_prefix(mock_whois, mock_playwright):
    """Test that 'www.' is correctly stripped from the domain."""
    url = "https://www.google.com/search?q=test"
    result = get_source_triage(url)
    assert result.domain == "google.com"

def test_get_source_triage_invalid_url(mock_whois, mock_playwright):
    """Test a malformed URL."""
    url = "not_a_url"
    result = get_source_triage(url)
    assert "Failed to parse URL" in result.error
    assert result.domain == "Unknown"