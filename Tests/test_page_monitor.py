import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock, mock_open

# The application instance to be tested

from chimera_intel.core.page_monitor import page_monitor_app, run_page_monitor

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
    assert "Successfully scheduled page monitor" in result.stdout
    mock_add_job.assert_called_once()
    call_args = mock_add_job.call_args[1]
    assert call_args["cron_schedule"] == "0 0 * * *"
    assert call_args["kwargs"]["url"] == "https://example.com"


# --- Tests for the Core Monitor Function ---


@patch("chimera_intel.core.page_monitor.send_slack_notification")
@patch("chimera_intel.core.page_monitor.sync_playwright")
@patch("os.path.exists")
@patch(
    "builtins.open", new_callable=mock_open, read_data="This is the old baseline text."
)
@patch("os.rename")
@patch(
    "chimera_intel.core.page_monitor.compare_images", return_value=0.90
)  # Simulate image change
def test_run_page_monitor_change_detected(
    mock_compare_img,
    mock_rename,
    mock_open_file,
    mock_exists,
    mock_playwright,
    mock_slack,
):
    """
    Tests the core monitor function when a significant change is detected.
    """
    # Arrange: Simulate that a baseline already exists

    mock_exists.return_value = True

    # Mock Playwright to return new content

    mock_page = MagicMock()
    mock_page.inner_text.return_value = "This is the NEW page text."
    mock_browser = MagicMock()
    mock_browser.new_page.return_value = mock_page
    mock_playwright.return_value.__enter__.return_value.chromium.launch.return_value = (
        mock_browser
    )

    # Act

    run_page_monitor(url="https://example.com")

    # Assert

    mock_slack.assert_called_once()
    assert "Significant change detected" in mock_slack.call_args[0][0]


@patch("chimera_intel.core.page_monitor.sync_playwright")
@patch("os.path.exists")
@patch("os.rename")
def test_run_page_monitor_creates_new_baseline(
    mock_rename, mock_exists, mock_playwright
):
    """
    Tests that the monitor creates a new baseline if one doesn't exist.
    """
    # Arrange: Simulate that a baseline does NOT exist

    mock_exists.return_value = False

    mock_page = MagicMock()
    mock_page.inner_text.return_value = "Initial text."
    mock_browser = MagicMock()
    mock_browser.new_page.return_value = mock_page
    mock_playwright.return_value.__enter__.return_value.chromium.launch.return_value = (
        mock_browser
    )

    # Act

    run_page_monitor(url="https://new-site.com")

    # Assert that os.rename was called to create the new baseline file

    mock_rename.assert_called()
