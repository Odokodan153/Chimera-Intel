import pytest
import pytest_asyncio
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock
import json

from chimera_intel.core.global_monitor import global_monitor_app, check_for_keyword_mentions
from chimera_intel.cli import app # Main app
from chimera_intel.core.schemas import PageSnapshot # Import for mocking

runner = CliRunner()

@pytest.mark.asyncio
@patch("chimera_intel.core.global_monitor.search_google", new_callable=AsyncMock)
@patch("chimera_intel.core.global_monitor.save_page_snapshot")
@patch("chimera_intel.core.global_monitor.send_slack_notification")
@patch("chimera_intel.core.global_monitor.CONFIG")
async def test_check_for_keyword_mentions_new_result(
    mock_config, mock_slack, mock_save, mock_search
):
    """Test the core job function when a new result is found."""
    
    # 1. Setup mocks
    mock_config.notifications.slack_webhook_url = "http://fake.slack.url"
    
    # Mock search_google
    mock_search.return_value = [
        {"url": "http://new.com", "title": "New Result"}
    ]
    
    # Mock save_page_snapshot to return (change_detected=True, old_hash="old-hash")
    mock_save.return_value = (True, "old-hash-123")
    
    # Mock get_latest_snapshot_hash (used for diffing)
    with patch("chimera_intel.core.global_monitor.get_latest_snapshot_hash") as mock_get_old:
        mock_get_old.return_value = PageSnapshot(
            url="job-123",
            hash="old-hash-123",
            timestamp="...",
            content=json.dumps([{"url": "http://old.com", "title": "Old Result"}])
        )
        
        # 2. Run the job
        await check_for_keyword_mentions(
            job_id="job-123", 
            keyword="TestKeyword", 
            target="TestTarget"
        )

    # 3. Assertions
    # Check search was called correctly
    mock_search.assert_called_with('"TestKeyword" AND "TestTarget"', num_results=10)
    
    # Check save_page_snapshot was called with the new hash
    mock_save.assert_called_once()
    assert mock_save.call_args[0][0] == "job-123" # url == job_id
    assert mock_save.call_args[0][2] == json.dumps( # content
        [{"url": "http://new.com", "title": "New Result"}]
    ) 
    
    # Check notification was sent
    mock_slack.assert_called_once()
    assert "New mention detected" in mock_slack.call_args[0][1]
    assert "http://new.com" in mock_slack.call_args[0][1]


@patch("chimera_intel.core.scheduler.add_job")
def test_cli_add_monitor(mock_add_job):
    """Test the 'add' CLI command."""
    
    result = runner.invoke(
        app, # Use main app
        [
            "global-mon", "add", # Command from plugin
            "--keyword", "Acme Corp",
            "--target", "Project X",
            "--schedule", "0 0 * * *"
        ]
    )
    
    assert result.exit_code == 0
    assert "Successfully scheduled keyword monitor" in result.stdout
    assert "Keyword: Acme Corp" in result.stdout
    
    # Check that the scheduler was called correctly
    mock_add_job.assert_called_once()
    kwargs = mock_add_job.call_args[1]['kwargs']
    assert kwargs['keyword'] == "Acme Corp"
    assert kwargs['target'] == "Project X"
    assert "gmon_" in mock_add_job.call_args[1]['job_id']