import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock

# The application instance to be tested

from chimera_intel.core.dark_web_monitor import (
    dark_web_monitor_app,
    run_dark_web_monitor,
)

runner = CliRunner()

# --- Tests for the Command ---


@patch("chimera_intel.core.dark_web_monitor.add_job")
def test_add_dark_web_monitor_command(mock_add_job):
    """
    Tests that the 'add' command correctly calls the scheduler.
    """
    result = runner.invoke(
        dark_web_monitor_app,
        [
            "add",
            "--keywords",
            "mycompany.com, secret-project",
            "--schedule",
            "0 0 * * *",
        ],
    )

    assert result.exit_code == 0
    assert "Successfully scheduled dark web monitor." in result.stdout
    mock_add_job.assert_called_once()
    call_args = mock_add_job.call_args[1]
    assert call_args["cron_schedule"] == "0 0 * * *"
    assert call_args["kwargs"]["keywords"] == ["mycompany.com", "secret-project"]


# --- Tests for the Core Monitor Function ---


@pytest.mark.asyncio
@patch("chimera_intel.core.dark_web_monitor.send_slack_notification")
@patch("chimera_intel.core.dark_web_monitor.send_teams_notification")
async def test_run_dark_web_monitor_keyword_found(mock_teams, mock_slack, mocker):
    """
    Tests the core monitor function when a keyword is found.
    """
    # Mock the config

    mock_config = MagicMock()
    mock_config.modules.dark_web.tor_proxy_url = "socks5://localhost:9050"
    mocker.patch("chimera_intel.core.dark_web_monitor.CONFIG", mock_config)

    # Mock the HTTP client and response

    mock_response = MagicMock()
    mock_response.text = "<html><body><h1>Leaked Data</h1><p>We have data from mycompany.com for sale.</p></body></html>"
    mock_response.raise_for_status.return_value = None

    mock_async_client = AsyncMock()
    mock_async_client.get.return_value = mock_response

    mocker.patch(
        "chimera_intel.core.dark_web_monitor.get_async_http_client",
        return_value=mock_async_client,
    )

    # Mock file system operations

    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open())

    # Run the monitor

    await run_dark_web_monitor(keywords=["mycompany.com"])

    # Assert that notifications were sent

    mock_slack.assert_called_once()
    mock_teams.assert_called_once()
    assert "Keyword 'mycompany.com' detected" in mock_slack.call_args[0][0]
