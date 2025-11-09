import unittest
from unittest.mock import patch, Mock
from src.chimera_intel.core.prodint import app, ProdInt, check_for_changes
import httpx
import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock

class TestProdInt(unittest.TestCase):
    def setUp(self):
        self.prodint = ProdInt()

    @patch("src.chimera_intel.core.prodint.WebPage")
    @patch("src.chimera_intel.core.prodint.Wappalyzer")
    def test_digital_teardown(self, mock_wappalyzer_class, mock_webpage_class):
        # --- Setup Mocks ---
        # Mock the WebPage object that is created

        mock_webpage_instance = Mock()
        mock_webpage_class.new_from_url.return_value = mock_webpage_instance

        # Mock the Wappalyzer instance and its analyze method

        mock_wappalyzer_instance = Mock()
        mock_wappalyzer_instance.analyze_with_versions.return_value = {
            "JavaScript Frameworks": {"React": ["18.2.0"]}
        }
        mock_wappalyzer_class.return_value = mock_wappalyzer_instance

        # --- Run Test ---

        result = self.prodint.digital_teardown("https://example.com")

        # --- Assertions ---

        self.assertIn("JavaScript Frameworks", result)
        self.assertEqual(result["JavaScript Frameworks"]["React"][0], "18.2.0")
        mock_webpage_class.new_from_url.assert_called_once_with("https://example.com")
        mock_wappalyzer_instance.analyze_with_versions.assert_called_once_with(
            mock_webpage_instance
        )

    @patch("src.chimera_intel.core.prodint.AppStore")
    def test_analyze_churn_risk(self, mock_app_store_class):
        # --- Setup Mocks ---
        # Mock the AppStore instance, its 'review' method, and 'reviews' attribute

        mock_app_store_instance = Mock()
        mock_app_store_instance.reviews = [
            {"review": "This is the best app ever!"},  # Positive
            {"review": "I hate this, it is terrible."},  # Negative
            {"review": "It is okay, not great."},  # Neutral
        ]
        mock_app_store_class.return_value = mock_app_store_instance

        # --- Run Test ---

        result = self.prodint.analyze_churn_risk("com.example.app", review_count=3)

        # --- Assertions ---

        self.assertEqual(result["reviews_analyzed"], 3)
        self.assertEqual(result["positive_sentiment"], "33.3%")
        self.assertEqual(result["negative_sentiment"], "33.3%")
        self.assertEqual(result["estimated_churn_risk"], "Medium")
        mock_app_store_class.assert_called_once_with(
            country="us", app_name="com.example.app"
        )
        mock_app_store_instance.review.assert_called_once_with(how_many=3)

    def test_find_feature_gaps(self):
        # This test is logically correct and needs no changes.

        our_features = ["A", "B"]
        competitor_features = ["B", "C"]
        requested_features = ["C", "D"]

        result = self.prodint.find_feature_gaps(
            our_features, competitor_features, requested_features
        )

        self.assertEqual(result["competitor_advantages"], ["C"])
        self.assertEqual(result["unaddressed_market_needs"], ["D"])



runner = CliRunner()

# Mock HTML content
MOCK_FEATURES_HTML = """
<html>
<body>
    <section class="features">
        <h2>Our Features</h2>
        <ul>
            <li>Feature One</li>
            <li>Feature Two</li>
            <li>Shared Feature</li>
        </ul>
    </section>
</body>
</html>
"""

MOCK_COMPETITOR_HTML = """
<html>
<body>
    <div id="pricing-plans">
        <div class="plan">
            <h3>Basic</h3>
            <ul>
                <li>Feature Three</li>
                <li>Feature Four</li>
                <li>Shared Feature</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""

MOCK_CATALOG_HTML = """
<html>
<body>
    <div class="product-list">
        <div class="product-card">
            <h3 class="product-name">Product Alpha</h3>
            <span class="price">$19.99</span>
        </div>
        <div class="product-card">
            <h3 class="product-name">Product Beta</h3>
            <span class="price">$29.99</span>
        </div>
        <li class="product">
            <a href="/p/gamma" class="product-title">Product Gamma</a>
            <div class="amount-wrapper">
                <span class="price-amount">$39.99</span>
            </div>
        </li>
    </div>
</body>
</html>
"""

@pytest.fixture
def mock_http_client():
    """Mocks the get_async_http_client context manager."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(return_value=mock_response)
    
    # This setup mocks the async context manager
    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_client
    
    with patch("chimera_intel.core.prodint.get_async_http_client", return_value=mock_cm) as mock_cm_constructor:
        yield mock_client, mock_response

@pytest.mark.asyncio
async def test_scrape_features_from_page(mock_http_client):
    mock_client, mock_response = mock_http_client
    mock_response.text = MOCK_FEATURES_HTML
    
    prodint = ProdInt()
    features = await prodint.scrape_features_from_page("https://example.com/features")
    
    mock_client.get.assert_called_with("https://example.com/features", follow_redirects=True, timeout=20.0)
    assert "Feature One" in features
    assert "Feature Two" in features
    assert "Shared Feature" in features
    assert len(features) == 3

@pytest.mark.asyncio
async def test_scrape_ecommerce_catalog(mock_http_client):
    mock_client, mock_response = mock_http_client
    mock_response.text = MOCK_CATALOG_HTML

    prodint = ProdInt()
    products = await prodint.scrape_ecommerce_catalog("https://example.com/store")

    mock_client.get.assert_called_with("https://example.com/store", follow_redirects=True, timeout=20.0)
    assert len(products) == 3
    assert {"name": "Product Alpha", "price": "$19.99"} in products
    assert {"name": "Product Beta", "price": "$29.99"} in products
    assert {"name": "Product Gamma", "price": "$39.99"} in products

def test_feature_gaps_command(mocker):
    # Mock the async scraper functions
    mock_scrape_ours = AsyncMock(return_value=["Feature One", "Shared Feature"])
    mock_scrape_theirs = AsyncMock(return_value=["Feature Two", "Shared Feature"])
    
    mocker.patch.object(ProdInt, "scrape_features_from_page", side_effect=[
        mock_scrape_ours(), mock_scrape_theirs()
    ])
    
    # Mock the internal gap finder
    mock_gap_finder = mocker.patch.object(ProdInt, "find_feature_gaps", return_value={
        "our_advantages_vs_requested": ["Feature One"],
        "competitor_advantages_vs_requested": ["Feature Two"],
        "unaddressed_market_needs": ["API"],
    })

    result = runner.invoke(
        app,
        [
            "feature-gaps",
            "--our-url",
            "https://oursite.com",
            "--competitor-url",
            "https://theirsite.com",
            "--requested",
            "Feature One, Feature Two, Shared Feature, API",
        ],
    )

    assert result.exit_code == 0
    assert "Feature Gap Analysis Results" in result.stdout
    assert '"unaddressed_market_needs": [\n    "api"\n  ]' in result.stdout # find_feature_gaps lowercases
    assert '"our_advantages_vs_requested": [\n    "feature one"\n  ]' in result.stdout
    
    # Check that find_feature_gaps was called correctly
    mock_gap_finder.assert_called_with(
        ["Feature One", "Shared Feature"],
        ["Feature Two", "Shared Feature"],
        ["Feature One", "Feature Two", "Shared Feature", "API"]
    )

def test_monitor_changelog_command(mocker):
    mock_add_job = mocker.patch("chimera_intel.core.prodint.add_job")
    
    url_to_monitor = "https://example.com/changelog"
    cron_schedule = "0 0 * * *"
    
    result = runner.invoke(
        app,
        [
            "monitor-changelog",
            "--url",
            url_to_monitor,
            "--schedule",
            cron_schedule,
        ],
    )
    
    assert result.exit_code == 0
    assert "Successfully scheduled product page monitor" in result.stdout
    assert f"URL: {url_to_monitor}" in result.stdout
    assert f"Schedule: {cron_schedule}" in result.stdout

    # Check that the scheduler's add_job was called correctly
    mock_add_job.assert_called_once()
    call_args = mock_add_job.call_args[1]
    assert call_args["func"] == check_for_changes # Verifies reuse
    assert call_args["trigger"] == "cron"
    assert call_args["cron_schedule"] == cron_schedule
    assert call_args["kwargs"]["url"] == url_to_monitor
    assert "prodint_monitor_" in call_args["job_id"]


def test_scrape_catalog_command(mocker):
    mock_scrape = AsyncMock(return_value=[
        {"name": "Scraped Product", "price": "$99"}
    ])
    mocker.patch.object(ProdInt, "scrape_ecommerce_catalog", mock_scrape)

    result = runner.invoke(
        app,
        [
            "scrape-catalog",
            "https://example.com/catalog",
        ],
    )

    assert result.exit_code == 0
    assert "Successfully scraped 1 products" in result.stdout
    assert '"name": "Scraped Product"' in result.stdout
    assert '"price": "$99"' in result.stdout
if __name__ == "__main__":
    unittest.main()
