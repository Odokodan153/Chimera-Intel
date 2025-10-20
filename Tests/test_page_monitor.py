import unittest
import asyncio
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.page_monitor import page_monitor_app

runner = CliRunner()


class TestPageMonitor(unittest.TestCase):
    """Test cases for the Page Monitor module."""

    # --- CLI Tests ---

    @patch("chimera_intel.core.page_monitor.add_job")
    @patch("chimera_intel.core.page_monitor.console.print")
    def test_add_page_monitor_command(self, mock_console, mock_add_job):
        """Tests the 'add' command for adding a new page to monitor."""
        # Arrange

        mock_add_job.return_value = None

        # Act

        result = runner.invoke(
            page_monitor_app,
            ["add", "--url", "https://example.com/about", "--schedule", "* * * * *"],
        )

        # Assert

        self.assertEqual(result.exit_code, 0, result.stdout)
        mock_add_job.assert_called_once()
        mock_console.assert_any_call(
            "[bold green]✅ Successfully scheduled web page monitor.[/bold green]"
        )

    @patch("chimera_intel.core.page_monitor.save_page_snapshot")
    @patch("chimera_intel.core.page_monitor.get_async_http_client")
    def test_check_for_changes_with_changes(
        self, mock_get_client, mock_save_snapshot
    ):
        """Tests the 'check' command when changes are detected."""
        # Arrange

        mock_save_snapshot.return_value = (True, "old_hash")

        # Act

        from chimera_intel.core.page_monitor import check_for_changes

        asyncio.run(check_for_changes("https://example.com", "test_job"))

        # Assert

        mock_save_snapshot.assert_called_once()

    @patch("chimera_intel.core.page_monitor.save_page_snapshot")
    @patch("chimera_intel.core.page_monitor.get_async_http_client")
    def test_check_for_changes_no_changes(
        self, mock_get_client, mock_save_snapshot
    ):
        """Tests the 'check' command when no changes are detected."""
        # Arrange

        mock_save_snapshot.return_value = (False, "same_hash")

        # Act

        from chimera_intel.core.page_monitor import check_for_changes

        asyncio.run(check_for_changes("https://example.com", "test_job"))

        # Assert

        mock_save_snapshot.assert_called_once()


if __name__ == "__main__":
    unittest.main()