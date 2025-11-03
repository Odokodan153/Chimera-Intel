import pytest
import httpx
from unittest.mock import MagicMock, AsyncMock, patch

# --- Mock core instances BEFORE importing active_recon ---
# This is crucial as active_recon imports them at the module level
mock_aia = MagicMock()
mock_aia.generate_analysis = AsyncMock(return_value="AIA Analysis Result")

mock_reporter = MagicMock()
mock_reporter.create_dossier = AsyncMock(return_value="dossier-123")

mock_user_manager = MagicMock()
mock_user_manager.check_active_recon_consent = AsyncMock(return_value=True)
mock_user_manager.get_current_user = MagicMock(return_value=MagicMock(id="user-cli", username="cli_user"))

mock_auto_manager = MagicMock()
mock_auto_manager.register_playbook = MagicMock()


modules = {
    "src.chimera_intel.core.aia_framework": MagicMock(aia_framework=mock_aia),
    "src.chimera_intel.core.reporter": MagicMock(reporter=mock_reporter),
    "src.chimera_intel.core.user_manager": MagicMock(user_manager=mock_user_manager),
    "src.chimera_intel.core.automation": MagicMock(automation_manager=mock_auto_manager),
    "src.chimera_intel.core.config_loader": MagicMock(),
    "src.chimera_intel.core.logger_config": MagicMock(setup_logging=MagicMock()),
    "bs4": MagicMock(), # Mock BeautifulSoup
}

# Apply patches
with patch.dict("sys.modules", modules):
    from src.chimera_intel.core.active_recon import (
        run_active_recon_playbook,
        register_active_recon_playbooks,
        _safe_crawl,
        http_client # We need to patch the client used by the module
    )
    # <<< FIX: Import Playbook to resolve Pylance error >>>
    from src.chimera_intel.core.automation import Playbook


@pytest.fixture(autouse=True)
def reset_mocks():
    """Reset mocks before each test."""
    mock_aia.reset_mock()
    mock_reporter.reset_mock()
    mock_user_manager.reset_mock()
    mock_auto_manager.reset_mock()
    mock_user_manager.check_active_recon_consent.return_value = True # Default to consent
    
@pytest.mark.asyncio
async def test_run_playbook_consent_denied():
    """
    Tests that the playbook exits immediately if consent is denied.
    """
    mock_user_manager.check_active_recon_consent.return_value = False
    
    user_id = "user-test"
    target = "example.com"
    
    result = await run_active_recon_playbook(user_id, target)
    
    mock_user_manager.check_active_recon_consent.assert_called_once_with(user_id, target)
    assert "consent not provided" in result
    mock_reporter.create_dossier.assert_not_called()
    mock_aia.generate_analysis.assert_not_called()

@pytest.mark.asyncio
@patch('src.chimera_intel.core.active_recon.http_client', new_callable=AsyncMock)
async def test_run_playbook_consent_granted(mock_http_client):
    """
    Tests the full playbook execution flow when consent is granted.
    Mocks the http_client used by the module.
    """
    # Mock HTTP client and its responses
    mock_crawl_resp = AsyncMock(spec=httpx.Response)
    mock_crawl_resp.status_code = 200
    mock_crawl_resp.headers = {"content-type": "text/html"}
    mock_crawl_resp.text = '<html><a href="/page1">Page 1</a></html>'
    mock_crawl_resp.url = "https://example.com"

    mock_api_resp = AsyncMock(spec=httpx.Response)
    mock_api_resp.status_code = 200
    mock_api_resp.headers = {"content-type": "application/json"}
    mock_api_resp.json = MagicMock(return_value={"openapi": "3.0"})
    mock_api_resp.url = "https://example.com/openapi.json"

    mock_dir_resp = AsyncMock(spec=httpx.Response)
    mock_dir_resp.status_code = 200
    mock_dir_resp.headers = {"content-type": "text/plain"}
    mock_dir_resp.url = "https://example.com/admin"

    mock_404 = AsyncMock(spec=httpx.Response, status_code=404)
    mock_404.raise_for_status = MagicMock(side_effect=httpx.HTTPStatusError("Not Found", request=MagicMock(), response=mock_404))

    mock_http_client.head.side_effect = [
        mock_crawl_resp, mock_404, mock_api_resp, mock_404, mock_404, mock_404, 
        mock_404, mock_404, mock_404, mock_404, mock_dir_resp, mock_404, 
        mock_404, mock_404, mock_404, mock_404, mock_404,
    ]
    mock_http_client.get.side_effect = [
        mock_crawl_resp, mock_api_resp, mock_404,
    ]

    user_id = "user-test"
    target = "example.com"
    
    with patch('src.chimera_intel.core.active_recon.BeautifulSoup') as mock_soup:
        mock_soup_instance = mock_soup.return_value
        mock_link = MagicMock()
        mock_link.__getitem__.return_value = "/page1"
        mock_soup_instance.find_all.return_value = [mock_link]

        dossier_id = await run_active_recon_playbook(user_id, target)
    
    mock_user_manager.check_active_recon_consent.assert_called_once_with(user_id, target)
    mock_aia.generate_analysis.assert_called_once()
    mock_reporter.create_dossier.assert_called_once()
    assert dossier_id == "dossier-123"
    
    _, kwargs = mock_reporter.create_dossier.call_args
    dossier_data = kwargs.get("data", {})
    
    assert dossier_data['target'] == "example.com"
    assert "https://example.com/admin" in dossier_data['raw_results']['dir_enum']
    assert "https://example.com/page1" in dossier_data['raw_results']['crawling']
    assert "https://example.com/openapi.json" in dossier_data['raw_results']['api_discovery']
    assert dossier_data['aia_analysis'] == "AIA Analysis Result"

def test_register_playbooks():
    """
    Tests that the playbook is correctly registered with the AutomationManager.
    """
    register_active_recon_playbooks()
    
    mock_auto_manager.register_playbook.assert_called_once()
    args, _ = mock_auto_manager.register_playbook.call_args
    registered_playbook = args[0]
    
    assert isinstance(registered_playbook, Playbook) # This is the line that failed
    assert registered_playbook.name == "run_full_active_recon"
    assert "target_domain" in registered_playbook.required_params