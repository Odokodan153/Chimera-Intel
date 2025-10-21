import pytest
import typer  # <-- FIX 1: Import typer
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock

# Import the specific app instance for the command being tested
from chimera_intel.core.dark_web_monitor import (
    dark_web_monitor_app,
    run_dark_web_monitor,
)

runner = CliRunner()

# FIX 2: Wrap the sub-app in a parent app
app = typer.Typer()
app.add_typer(dark_web_monitor_app, name="monitor")


# --- Tests for the Command ---


@patch("chimera_intel.core.dark_web_monitor.add_job")
def test_add_dark_web_monitor_command(mock_add_job):
    """
    Tests that the 'add' command correctly calls the scheduler.
    """
    # FIX 3: Invoke the parent 'app' with the full command 'monitor add'
    result = runner.invoke(
        app,  # Use the parent app
        [
            "monitor",  # Add the sub-command name
            "add",
            "--keywords",
            "mycompany.com, secret-project",
            "--schedule",
            "0 0 * * *",
        ],
    )

    # Assert that the command runs successfully
    assert result.exit_code == 0, f"CLI command failed: {result.stdout}"
    assert "Successfully scheduled dark web monitor." in result.stdout

    # Verify that the scheduler was called with the correct parameters
    mock_add_job.assert_called_once()
    call_args = mock_add_job.call_args[1]
    assert call_args["cron_schedule"] == "0 0 * * *"
    assert call_args["kwargs"]["keywords"] == ["mycompany.com", "secret-project"]


# --- Tests for the Core Monitor Function ---


@pytest.mark.asyncio
@patch("chimera_intel.core.dark_web_monitor.send_slack_notification")
@patch("chimera_intel.core.dark_web_monitor.send_teams_notification")
@patch(
    "chimera_intel.core.dark_web_monitor.get_dark_web_targets",
    return_value=["http://test-onion-site.onion"],
)
async def test_run_dark_web_monitor_keyword_found(
    mock_get_targets, mock_teams, mock_slack, mocker
):
    """
    Tests the core monitor function when a keyword is found.
    """
    # Mock the configuration object with all necessary attributes
    mock_config = MagicMock()
    mock_config.modules.dark_web.tor_proxy_url = "socks5://localhost:9050"
    mock_config.notifications.slack_webhook_url = "https://fake-slack-webhook.com"
    mock_config.notifications.teams_webhook_url = "https://fake-teams-webhook.com"
    mocker.patch("chimera_intel.core.dark_web_monitor.CONFIG", mock_config)

    # Mock the HTTP client and its response
    mock_response = MagicMock()
    mock_response.text = "<html><body><h1>Leaked Data</h1><p>We have data from mycompany.com for sale.</p></body></html>"
    mock_response.raise_for_status.return_value = None

    # Properly mock the async context manager for the HTTP client
    mock_async_client = AsyncMock()
    mock_async_client.get.return_value = mock_response

    mock_context_manager = AsyncMock()
    mock_context_manager.__aenter__.return_value = mock_async_client

    mocker.patch(
        "chimera_intel.core.dark_web_monitor.get_async_http_client",
        return_value=mock_context_manager,
    )

    # Mock file system operations to prevent actual file creation
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("os.makedirs")
    mocker.patch("builtins.open", mocker.mock_open())

    # Execute the monitor function
    await run_dark_web_monitor(keywords=["mycompany.com"])

    # Assert that both Slack and Teams notifications were sent
    mock_slack.assert_called_once()
    mock_teams.assert_called_once()
    
    # <--- FIX: Check the second argument (index 1), which is the message,
    # not the first argument (index 0), which is the URL.
    assert "Keyword 'mycompany.com' detected" in mock_slack.call_args[0][1]