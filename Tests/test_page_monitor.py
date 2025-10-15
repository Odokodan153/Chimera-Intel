from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
import asyncio

# The application instance to be tested


from chimera_intel.core.page_monitor import page_monitor_app, check_for_changes

runner = CliRunner()

# --- Tests for the Command ---


@patch("chimera_intel.core.page_monitor.add_job")
def test_add_page_monitor_command(mock_add_job):
    """
    Tests that the 'add' command correctly calls the scheduler.
    """
    result = runner.invoke(
        page_monitor_app,
        ["add", "--url", "https://example.com", "--schedule", "0 0 * * *"],
    )

    assert result.exit_code == 0
    assert "Successfully scheduled web page monitor" in result.stdout
    mock_add_job.assert_called_once()
    call_args = mock_add_job.call_args[1]
    assert call_args["cron_schedule"] == "0 0 * * *"
    assert call_args["kwargs"]["url"] == "https://example.com"


# --- Tests for the Core Monitor Function ---


@patch("chimera_intel.core.page_monitor.send_slack_notification")
@patch("chimera_intel.core.page_monitor.save_page_snapshot")
@patch("chimera_intel.core.page_monitor.get_async_http_client")
@patch("chimera_intel.core.page_monitor.CONFIG")
def test_check_for_changes_change_detected(
    mock_config,
    mock_get_client,
    mock_save_snapshot,
    mock_slack,
):
    """
    Tests the core monitor function when a significant change is detected.
    """
    # Arrange: Simulate that a change is detected

    mock_save_snapshot.return_value = (True, "old_hash")
    mock_config.notifications.slack_webhook_url = (
        "https://hooks.slack.com/services/FAKE/WEBHOOK/URL"
    )

    # Mock the HTTP client to return new content

    async def mock_get(*args, **kwargs):
        class MockResponse:
            def __init__(self):
                self.text = "This is the NEW page text."
                self.status_code = 200

            def raise_for_status(self):
                pass

        return MockResponse()

    mock_client = MagicMock()
    mock_client.get = MagicMock(side_effect=mock_get)
    # This is to handle the async context manager

    mock_get_client.return_value.__aenter__.return_value = mock_client

    # Act

    asyncio.run(check_for_changes(url="https://example.com", job_id="test_job"))

    # Assert

    mock_slack.assert_called_once()
    assert "Significant change detected" in mock_slack.call_args[1]["message"]


@patch("chimera_intel.core.page_monitor.save_page_snapshot")
@patch("chimera_intel.core.page_monitor.get_async_http_client")
def test_check_for_changes_creates_new_baseline(
    mock_get_client,
    mock_save_snapshot,
):
    """
    Tests that the monitor creates a new baseline if one doesn't exist.
    """
    # Arrange: Simulate that no change is detected (first run)

    mock_save_snapshot.return_value = (False, None)

    # Mock the HTTP client to return new content

    async def mock_get(*args, **kwargs):
        class MockResponse:
            def __init__(self):
                self.text = "Initial text."
                self.status_code = 200

            def raise_for_status(self):
                pass

        return MockResponse()

    mock_client = MagicMock()
    mock_client.get = MagicMock(side_effect=mock_get)
    # This is to handle the async context manager

    mock_get_client.return_value.__aenter__.return_value = mock_client

    # Act

    asyncio.run(check_for_changes(url="https://new-site.com", job_id="test_job"))

    # Assert that save_page_snapshot was called to create the new baseline file

    mock_save_snapshot.assert_called()
