import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, mock_open
import datetime
import json

from chimera_intel.core.pricing_intel import app, PRICE_HISTORY_FILE

runner = CliRunner()

# Mock HTML content for parsing tests
MOCK_HTML_SIMPLE = """
<html>
    <body>
        <span class="msrp"> $100.00 </span>
        <span class="sale"> $79.99 </span>
    </body>
</html>
"""

MOCK_HTML_NO_SALE = """
<html>
    <body>
        <span class="price">£49.99</span>
    </body>
</html>
"""

MOCK_PRICE_ENTRY = {
    "url": "https://example.com/product1",
    "timestamp": "2025-10-10T10:00:00",
    "list_price": 110.0,
    "sale_price": 99.99,
    "currency": "USD"
}


@pytest.fixture
def mock_file_system():
    """Mocks the file system for the JSON price historian."""
    # Mock file content
    mock_history_data = [MOCK_PRICE_ENTRY]
    mock_history_json = json.dumps(mock_history_data)

    # Patch os.path.exists and open
    with patch("os.path.exists") as mock_exists, \
         patch("os.makedirs") as mock_makedirs, \
         patch("builtins.open", mock_open(read_data=mock_history_json)) as mock_file:
        
        # Default: File exists
        mock_exists.return_value = True
        
        yield mock_file, mock_exists


@pytest.fixture
def mock_http_client(httpx_mock):
    """Mocks the async HTTP client."""
    httpx_mock.add_response(url="https://example.com/product1", text=MOCK_HTML_SIMPLE)
    httpx_mock.add_response(url="https://example.com/product2", text=MOCK_HTML_NO_SALE)
    httpx_mock.add_response(url="https://example.com/promos", text="Big holiday sale! 50% off with code SAVEBIG")
    yield httpx_mock


@pytest.fixture
def mock_web_analyzer():
    """Mocks the call to Similarweb."""
    mock_traffic_data = {
        "visits": [
            {"date": "2025-08-01", "value": 10000},
            {"date": "2025-09-01", "value": 11000},
            {"date": "2025-10-01", "value": 15000},
        ]
    }
    with patch("chimera_intel.core.pricing_intel.get_traffic_similarweb", return_value=mock_traffic_data) as mock_get:
        yield mock_get


@patch("chimera_intel.core.pricing_intel.add_job")
def test_add_price_monitor_command(mock_add_job):
    """Tests the CLI command for adding a new price monitor job."""
    result = runner.invoke(
        app,
        [
            "add-monitor",
            "--url",
            "https://example.com/product1",
            "--list-selector",
            "span.msrp",
            "--sale-selector",
            "span.sale",
            "--schedule",
            "0 0 * * *",
        ],
    )
    assert result.exit_code == 0
    assert "Successfully scheduled" in result.stdout
    mock_add_job.assert_called_once()
    call_kwargs = mock_add_job.call_args[1]["kwargs"]
    assert call_kwargs["url"] == "https://example.com/product1"
    assert call_kwargs["list_price_selector"] == "span.msrp"
    assert call_kwargs["job_id"] is not None


@pytest.mark.asyncio
async def test_check_product_price_parsing(mock_http_client, mock_file_system):
    """Tests the core price checking function's parsing and file logic."""
    mock_file, _ = mock_file_system
    from chimera_intel.core.pricing_intel import check_product_price

    # Test with a sale price (which is different from the mock file)
    await check_product_price(
        url="https://example.com/product1", # Matches MOCK_PRICE_ENTRY URL
        job_id="test-job-1",
        list_price_selector="span.msrp",
        sale_price_selector="span.sale",
    )
    
    # It should have read the file
    mock_file.assert_any_call(PRICE_HISTORY_FILE, "r")
    # It should have written the new price
    mock_file.assert_any_call(PRICE_HISTORY_FILE, "w")
    
    # Find the call to json.dump
    write_call = next(c for c in mock_file().write.call_args_list)
    written_data = json.loads(write_call[0][0])
    
    assert len(written_data) == 2 # Old entry + new entry
    new_entry = written_data[1]
    assert new_entry["sale_price"] == 79.99
    assert new_entry["list_price"] == 100.0
    assert new_entry["currency"] == "USD"


@pytest.mark.asyncio
async def test_check_product_price_no_change(mock_http_client, mock_file_system):
    """Tests that no file write occurs if the price is unchanged."""
    mock_file, _ = mock_file_system
    from chimera_intel.core.pricing_intel import check_product_price

    # Create a new mock HTML that matches the price in the mock file
    MOCK_HTML_NO_CHANGE = """
    <html><body><span class="msrp">$110.0</span><span class="sale">$99.99</span></body></html>
    """
    
    # Patch httpx_mock for just this test
    with patch("chimera_intel.core.http_client.AsyncClient") as mock_async_client:
        mock_response = MagicMock()
        mock_response.text = MOCK_HTML_NO_CHANGE
        mock_response.raise_for_status = MagicMock()
        mock_async_client.return_value.__aenter__.return_value.get = MagicMock(return_value=mock_response)

        await check_product_price(
            url="https://example.com/product1", # Matches MOCK_PRICE_ENTRY URL
            job_id="test-job-no-change",
            list_price_selector="span.msrp",
            sale_price_selector="span.sale",
        )

    # It should have read the file
    mock_file.assert_any_call(PRICE_HISTORY_FILE, "r")
    
    # It should NOT have written the file
    write_calls = [c for c in mock_file.call_args_list if c[0][0] == PRICE_HISTORY_FILE and c[0][1] == "w"]
    assert len(write_calls) == 0


def test_detect_promotions_command(mock_http_client):
    """Tests the promotion detection CLI command."""
    result = runner.invoke(
        app,
        ["detect-promos", "--url", "https://example.com/promos"],
    )
    assert result.exit_code == 0
    assert "Promotion Analysis" in result.stdout
    assert "50% off" in result.stdout
    assert "holiday sale" in result.stdout
    assert "SAVEBIG" in result.stdout


@patch("chimera_intel.core.pricing_intel.API_KEYS")
@patch("chimera_intel.core.pricing_intel.resolve_target", return_value="example.com")
def test_check_elasticity_command(mock_resolve, mock_keys, mock_file_system, mock_web_analyzer):
    """Tests the price elasticity correlation command using the file system."""
    mock_keys.similarweb_api_key = "fake_key"
    
    result = runner.invoke(
        app,
        ["check-elasticity", "example.com", "--url", "https://example.com/product1"],
    )
    
    assert result.exit_code == 0
    assert "Price Elasticity Signal Analysis" in result.stdout
    assert "Recent Price History (from local file)" in result.stdout
    assert "2025-10-10: USD 99.99" in result.stdout
    assert "Monthly Traffic Data (from Similarweb)" in result.stdout
    assert "2025-10-01: 15000 visits" in result.stdout
    assert "Signal:" in result.stdout