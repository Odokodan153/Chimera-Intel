import unittest
from unittest.mock import patch
from typer.testing import CliRunner

from chimera_intel.core.page_monitor import monitor_app
from chimera_intel.core.schemas import PageMonitorResult

runner = CliRunner()


class TestPageMonitor(unittest.TestCase):
    """Test cases for the Page Monitor module."""

    # --- CLI Tests ---

    @patch("chimera_intel.core.page_monitor.PageMonitor.add_page_to_monitor")
    @patch("chimera_intel.core.page_monitor.resolve_target")
    def test_add_page_monitor_command(self, mock_resolve_target, mock_add_page):
        """Tests the 'add' command for adding a new page to monitor."""
        # Arrange

        mock_resolve_target.return_value = "example.com"
        mock_add_page.return_value = None

        # Act

        result = runner.invoke(
            monitor_app, ["add", "https://example.com/about", "--target", "example.com"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Added 'https://example.com/about' to monitor", result.stdout)
        mock_resolve_target.assert_called_with(
            "example.com", required_assets=["domain"]
        )
        mock_add_page.assert_called_with("https://example.com/about", "example.com")

    @patch("chimera_intel.core.page_monitor.PageMonitor.check_for_updates")
    @patch("chimera_intel.core.page_monitor.resolve_target")
    def test_check_updates_command_with_changes(
        self, mock_resolve_target, mock_check_updates
    ):
        """Tests the 'check' command when changes are detected."""
        # Arrange

        mock_resolve_target.return_value = "example.com"
        mock_check_updates.return_value = PageMonitorResult(
            target="example.com",
            url="https://example.com",
            has_changed=True,
            diff="--- a\n+++ b",
        )

        # Act

        result = runner.invoke(monitor_app, ["check", "--target", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Changes detected for example.com", result.stdout)
        self.assertIn("--- a", result.stdout)

    @patch("chimera_intel.core.page_monitor.PageMonitor.check_for_updates")
    @patch("chimera_intel.core.page_monitor.resolve_target")
    def test_check_updates_command_no_changes(
        self, mock_resolve_target, mock_check_updates
    ):
        """Tests the 'check' command when no changes are detected."""
        # Arrange

        mock_resolve_target.return_value = "example.com"
        mock_check_updates.return_value = PageMonitorResult(
            target="example.com", url="https://example.com", has_changed=False
        )

        # Act

        result = runner.invoke(monitor_app, ["check", "--target", "example.com"])

        # Assert

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("No changes detected", result.stdout)


if __name__ == "__main__":
    unittest.main()
