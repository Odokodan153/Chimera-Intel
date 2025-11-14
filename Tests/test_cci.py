# Chimera-Intel/Tests/test_cci.py
import pytest
import asyncio
import httpx
from typer.testing import CliRunner
from unittest.mock import MagicMock, AsyncMock
from chimera_intel.core.schemas import AlertLevel
# Mock essential modules before they are imported by cci
from .mocks import (
    mock_config_loader,
    mock_alert_manager,
    mock_rt_osint
)

# Apply mocks
mock_config_loader()
mock_alert_manager()
mock_rt_osint()

# Now import the module to be tested
from chimera_intel.core.cci import cci_app, get_rotating_ua, _plausible_domains_cache, _domain_cache_lock
from chimera_intel.core.config_loader import CONFIG, API_KEYS
from chimera_intel.core.alert_manager import alert_manager
from chimera_intel.core.rt_osint import check_clearnet, check_onion, save_seen_urls

runner = CliRunner()

@pytest.fixture(autouse=True)
def reset_caches():
    """Ensures caches are clear before each test."""
    global _plausible_domains_cache
    _plausible_domains_cache.clear()
    # Reset the lock to be safe
    global _domain_cache_lock
    _domain_cache_lock = asyncio.Lock()
    # Reset seen URLs
    mock_rt_osint(reset_seen=True)

@pytest.fixture
def mock_httpx(mocker):
    """Mocks httpx.AsyncClient."""
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = "Rank,Domain\n1,google.com\n2,youtube.com\n3,facebook.com"
    mock_client.__aenter__.return_value.get.return_value = mock_response
    
    mocker.patch("httpx.AsyncClient", return_value=mock_client)
    return mock_client

def test_get_rotating_ua(mocker):
    """Tests that a random UA is selected from the config."""
    ua_pool = ["ua1", "ua2", "ua3"]
    mocker.patch.object(CONFIG.modules.cci, 'user_agent_pool', ua_pool)
    
    results = set()
    for _ in range(20):
        results.add(get_rotating_ua())
    
    assert len(results) > 1
    assert all(ua in ua_pool for ua in results)

@pytest.mark.asyncio
async def test_cli_generate_chaff(mock_httpx, mocker):
    """Tests the chaff generation command."""
    # 1. Mock config and API keys
    mocker.patch.object(API_KEYS, 'scraperapi_api_key', 'test_key_123')
    mocker.patch.object(CONFIG.modules.cci, 'proxy_api_url', 'http://scraperapi:{API_KEY}@proxy.com:8001')
    mocker.patch.object(CONFIG.modules.cci, 'chaff_domain_source', 'http://fake-majestic.com')
    
    # 2. Mock the response for the chaff *requests*
    mock_chaff_response = MagicMock(spec=httpx.Response)
    mock_chaff_response.status_code = 200
    mock_httpx.__aenter__.return_value.get.side_effect = [
        # First call is for _load_plausible_domains
        MagicMock(status_code=200, text="Rank,Domain\n1,google.com\n2,youtube.com\n3,facebook.com\n4,real-target.com"),
        # Subsequent calls are the chaff requests
        mock_chaff_response,
        mock_chaff_response,
        mock_chaff_response
    ]

    # 3. Run the command
    result = runner.invoke(
        cci_app, 
        ["generate-chaff", "real-target.com", "--count", "3"]
    )
    
    assert result.exit_code == 0
    assert "CCI: Generating 3 chaff queries to mask 'real-target.com'..." in result.stdout
    assert "CCI: Loaded 4 plausible domains" in result.stdout
    assert "CCI: Chaff generation complete. Success/Tolerated: 3, Failed: 0" in result.stdout
    
    # 4. Verify httpx.AsyncClient was called with proxy
    mock_httpx_calls = mock_httpx.call_args_list
    assert len(mock_httpx_calls) > 0
    _, kwargs = mock_httpx_calls[0]
    assert "proxies" in kwargs
    assert kwargs["proxies"]["https://"] == "http://scraperapi:test_key_123@proxy.com:8001"

    # 5. Verify it didn't query the real_target
    get_calls = mock_httpx.__aenter__.return_value.get.call_args_list
    urls_called = [call[0][0] for call in get_calls]
    
    assert "http://fake-majestic.com" in urls_called # Load call
    assert "https://google.com" in urls_called
    assert "https://youtube.com" in urls_called
    assert "https://facebook.com" in urls_called
    assert "https://real-target.com" not in urls_called # Chaff logic should skip this

@pytest.mark.asyncio
async def test_cli_self_monitor_finds_match(mocker):
    """Tests that self-monitor finds a match and fires an alert."""
    # 1. Mock config
    assets = ["chimera-project", "1.2.3.4"]
    mocker.patch.object(CONFIG.modules.cci, 'self_monitor_assets', assets)
    
    # 2. Mock rt_osint functions to return a hit
    mock_hit = [
        ("chimera-project", "Leaked: Chimera Project Source Code", "http://onion-site.onion/leak")
    ]
    mocker.patch(
        "chimera_intel.core.rt_osint.check_clearnet", 
        AsyncMock(return_value=[])
    )
    mocker.patch(
        "chimera_intel.core.rt_osint.check_onion", 
        AsyncMock(return_value=mock_hit)
    )
    
    # 3. Mock the alert manager
    mock_alert_dispatch = mocker.patch.object(alert_manager, 'dispatch_alert')
    
    # 4. Mock the proxy connector (used by aiohttp)
    mocker.patch("aiohttp_socks.ProxyConnector.from_url", return_value=MagicMock())

    # 5. Run the command
    result = runner.invoke(cci_app, ["self-monitor"])
    
    assert result.exit_code == 0
    assert "ALERT: Found 1 new mentions of platform assets!" in result.stdout
    assert "http://onion-site.onion/leak" in result.stdout
    
    # 6. Verify alert was dispatched
    mock_alert_dispatch.assert_called_once_with(
        title="CCI Self-Monitor Alert: Platform Asset 'chimera-project' Found",
        message="A new public mention was found: 'Leaked: Chimera Project Source Code' at http://onion-site.onion/leak",
        level=AlertLevel.CRITICAL,
        provenance={"module": "cci.self-monitor", "url": "http://onion-site.onion/leak"},
        legal_flag="PLATFORM_EXPOSURE_INCIDENT"
    )
    
    # 7. Verify save_seen_urls was called
    save_seen_urls.assert_called_once()

@pytest.mark.asyncio
async def test_cli_self_monitor_no_match(mocker):
    """Tests that self-monitor finds no matches."""
    mocker.patch.object(CONFIG.modules.cci, 'self_monitor_assets', ["chimera"])
    mocker.patch("chimera_intel.core.rt_osint.check_clearnet", AsyncMock(return_value=[]))
    mocker.patch("chimera_intel.core.rt_osint.check_onion", AsyncMock(return_value=[]))
    mock_alert_dispatch = mocker.patch.object(alert_manager, 'dispatch_alert')
    mocker.patch("aiohttp_socks.ProxyConnector.from_url", return_value=MagicMock())

    result = runner.invoke(cci_app, ["self-monitor"])
    
    assert result.exit_code == 0
    assert "Self-monitor complete. No new mentions found." in result.stdout
    mock_alert_dispatch.assert_not_called()