import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock

from chimera_intel.core.channel_intel import app

runner = CliRunner()


@pytest.fixture
def mock_similarweb_sources():
    """Mocks the new call to Similarweb traffic-sources endpoint."""
    mock_traffic_data = {
        "search_organic": 0.55,
        "search_paid": 0.15,
        "direct": 0.20,
        "social": 0.05,
        "referrals": 0.05
    }
    # This patches the NEW function in channel_intel
    with patch("chimera_intel.core.channel_intel.get_traffic_sources_similarweb", 
                 new_callable=AsyncMock, 
                 return_value=mock_traffic_data) as mock_get:
        yield mock_get


@pytest.fixture
def mock_google_cse():
    """Mocks the new call to the Google CSE API."""
    # This is the real structure of a Google CSE response
    mock_search_results = {
        "items": [
            {"link": "https://reviews.com/great-product-review", "snippet": "..."},
            {"link": "https://coupons.com/great-product-coupon", "snippet": "..."},
            {"link": "https://example.com/blog-post", "snippet": "..."}, # Own domain
        ]
    }
    # This patches the NEW function in channel_intel
    with patch("chimera_intel.core.channel_intel._search_google_cse", 
                 new_callable=AsyncMock, 
                 return_value=mock_search_results) as mock_search:
        yield mock_search


@pytest.fixture
def mock_http_client(httpx_mock):
    """Mocks the async HTTP client for scraping search results."""
    # Page with affiliate links
    html_affiliate = """
    <html><body>
        <a href="https://example.com/product?ref=reviews123">Buy Now!</a>
        <a href="https://example.com/another?utm_medium=affiliate">Click</a>
    </body></html>
    """
    # Page with no affiliate links
    html_no_affiliate = """
    <html><body>
        <a href="https://example.com/product">Buy Now!</a>
    </body></html>
    """
    
    httpx_mock.add_response(url="https://reviews.com/great-product-review", text=html_affiliate)
    httpx_mock.add_response(url="https://coupons.com/great-product-coupon", text=html_no_affiliate)
    yield httpx_mock


@pytest.fixture
def mock_playwright():
    """Mocks the async_playwright library."""
    mock_ad_element = MagicMock()
    mock_text_element = MagicMock()
    mock_text_element.inner_text = AsyncMock(return_value="This is an ad")
    mock_ad_element.query_selector = AsyncMock(return_value=mock_text_element)
    mock_ad_element.screenshot = AsyncMock()

    mock_page = MagicMock()
    mock_page.goto = AsyncMock()
    mock_page.wait_for_selector = AsyncMock()
    mock_page.query_selector_all = AsyncMock(return_value=[mock_ad_element, mock_ad_element])
    
    mock_browser = MagicMock()
    mock_browser.new_page = AsyncMock(return_value=mock_page)
    mock_browser.close = AsyncMock()
    
    mock_playwright_manager = MagicMock()
    mock_playwright_manager.__aenter__ = AsyncMock(return_value=MagicMock(chromium=MagicMock(launch=AsyncMock(return_value=mock_browser))))
    mock_playwright_manager.__aexit__ = AsyncMock()

    with patch("chimera_intel.core.channel_intel.async_playwright", return_value=mock_playwright_manager) as mock:
        yield mock


@patch("chimera_intel.core.channel_intel.API_KEYS")
@patch("chimera_intel.core.channel_intel.resolve_target", return_value="example.com")
def test_analyze_traffic_mix(mock_resolve, mock_keys, mock_similarweb_sources):
    """Tests the real traffic mix analysis command."""
    mock_keys.similarweb_api_key = "fake_key"
    
    result = runner.invoke(app, ["analyze-mix", "example.com"])
    
    assert result.exit_code == 0
    assert "Analyzing real traffic mix for example.com" in result.stdout
    # Check for real (non-simulated) keys
    assert "traffic_mix_overview" in result.stdout
    assert "search_organic" in result.stdout
    assert "simulated_mix" not in result.stdout


@patch("chimera_intel.core.channel_intel.API_KEYS")
@patch("chimera_intel.core.channel_intel.resolve_target", return_value="example.com")
def test_find_affiliate_partners(mock_resolve, mock_keys, mock_google_cse, mock_http_client):
    """Tests the real affiliate partner hunting command."""
    mock_keys.google_api_key = "fake_google_key"
    mock_keys.google_cse_id = "fake_cse_id"
    
    result = runner.invoke(app, ["find-partners", "example.com"])
    
    assert result.exit_code == 0
    assert "Hunting for affiliates" in result.stdout
    assert "Searching Google CSE" in result.stdout
    assert "Scraping 2 unique pages" in result.stdout # 3 results, 1 is internal
    assert "potential_partners" in result.stdout
    assert "reviews.com/great-product-review" in result.stdout
    assert "ref=reviews123" in result.stdout
    # The coupon site had no matching links, so it shouldn't be listed
    assert "coupons.com" not in result.stdout


def test_scrape_ad_library(mock_playwright):
    """Tests the ad library scraping command."""
    with patch("os.makedirs", MagicMock()):
        result = runner.invoke(
            app,
            ["scrape-ads", "--query", "MyBrand", "--platform", "meta"],
        )
    
    assert result.exit_code == 0
    assert "Scraping meta ad library for 'MyBrand'" in result.stdout
    assert "Found 2 potential ad elements." in result.stdout
    assert "Successfully scraped 2 ads" in result.stdout
    assert "This is an ad" in result.stdout
    assert "screenshots/ads/meta/MyBrand_0.png" in result.stdout