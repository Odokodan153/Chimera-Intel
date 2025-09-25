import unittest
import psycopg2
from unittest.mock import patch
from chimera_intel.core.differ import (
    get_last_two_scans,
    format_diff_simple,
    analyze_diff_for_signals,
)
from chimera_intel.core.schemas import FormattedDiff, ProjectConfig, MicroSignal
from typer.testing import CliRunner
from chimera_intel.cli import app
from jsondiff import diff, insert

runner = CliRunner()


class TestDiffer(unittest.TestCase):
    """Extended test cases for the differ module."""

    @patch("chimera_intel.core.differ.get_db_connection")
    def test_get_last_two_scans_success(self, mock_get_conn):
        """Tests retrieving the last two scans from the database."""
        mock_conn = mock_get_conn.return_value
        mock_cursor = mock_conn.cursor.return_value
        # Simulate the database returning two records, with the latest first

        scan1_latest = '{"subdomains": ["a.com", "b.com"]}'
        scan2_previous = '{"subdomains": ["a.com"]}'
        mock_cursor.fetchall.return_value = [(scan1_latest,), (scan2_previous,)]

        latest, previous = get_last_two_scans("example.com", "footprint")

        self.assertIsNotNone(latest)
        self.assertIsNotNone(previous)
        self.assertEqual(latest["subdomains"], ["a.com", "b.com"])
        self.assertEqual(previous["subdomains"], ["a.com"])

    @patch("chimera_intel.core.differ.get_db_connection")
    def test_get_last_two_scans_not_enough_data(self, mock_get_conn):
        """Tests retrieval when there are fewer than two scans."""
        mock_conn = mock_get_conn.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = [('{"key": "value"}',)]  # Only one record

        latest, previous = get_last_two_scans("example.com", "footprint")
        self.assertIsNone(latest)
        self.assertIsNone(previous)

    @patch("chimera_intel.core.differ.get_db_connection")
    def test_get_last_two_scans_db_error(self, mock_get_conn):
        """Tests retrieval when a specific psycopg2.Error occurs."""
        # Simulate a database-level error

        mock_get_conn.side_effect = psycopg2.Error("Test DB Error")

        with patch("chimera_intel.core.differ.logger.error") as mock_logger:
            latest, previous = get_last_two_scans("example.com", "footprint")
            self.assertIsNone(latest)
            self.assertIsNone(previous)
            # Verify that the specific error was logged

            mock_logger.assert_called_with(
                "Database error fetching last two scans for '%s': %s",
                "example.com",
                mock_get_conn.side_effect,
            )

    def test_format_diff_simple_add_and_remove(self):
        """Tests the simplification of a jsondiff with added and removed keys."""
        old_scan = {"tech": ["React"], "users": {"admin": True}}
        new_scan = {"tech": ["React"], "users": {"guest": True}}

        raw_diff = diff(old_scan, new_scan, syntax="symmetric")
        formatted = format_diff_simple(raw_diff)

        self.assertIsInstance(formatted, FormattedDiff)
        self.assertIn("users.admin", formatted.removed)
        self.assertIn("users.guest", formatted.added)
        self.assertEqual(len(formatted.removed), 1)
        self.assertEqual(len(formatted.added), 1)

    def test_format_diff_simple_changed_value(self):
        """Tests the simplification of a jsondiff with a changed value."""
        old_scan = {"version": "1.0"}
        new_scan = {"version": "1.1"}

        raw_diff = diff(old_scan, new_scan, syntax="symmetric")
        formatted = format_diff_simple(raw_diff)

        self.assertIsInstance(formatted, FormattedDiff)
        self.assertIn("version: 1.0", formatted.removed)
        self.assertIn("version: 1.1", formatted.added)

    def test_analyze_diff_for_signals_new_ip(self):
        """Tests that a new IP address is correctly identified as a signal."""
        raw_diff = {"footprint": {"dns_records": {"A": {insert: ["1.2.3.4"]}}}}
        signals = analyze_diff_for_signals(raw_diff)
        self.assertEqual(len(signals), 1)
        self.assertIsInstance(signals[0], MicroSignal)
        self.assertEqual(signals[0].signal_type, "Infrastructure Change")
        self.assertIn("1.2.3.4", signals[0].description)

    def test_analyze_diff_for_signals_no_signals(self):
        """Tests that no signals are generated for an insignificant change."""
        raw_diff = {"some_other_field": {insert: "new_value"}}
        signals = analyze_diff_for_signals(raw_diff)
        self.assertEqual(len(signals), 0)

    @patch("chimera_intel.core.differ.get_last_two_scans")
    @patch("chimera_intel.core.differ.send_teams_notification")
    @patch("chimera_intel.core.differ.send_slack_notification")
    def test_cli_diff_command_with_changes_and_all_notifications(
        self, mock_slack, mock_teams, mock_get_scans
    ):
        """Tests the CLI command when changes are detected and both notification webhooks are set."""
        # Arrange: Mock the data and API keys

        mock_get_scans.return_value = ({"key": "new"}, {"key": "old"})
        with patch("chimera_intel.core.differ.API_KEYS") as mock_keys:
            mock_keys.slack_webhook_url = "fake_slack_url"
            mock_keys.teams_webhook_url = "fake_teams_url"

            # Act

            result = runner.invoke(
                app, ["analysis", "diff", "run", "footprint", "example.com"]
            )

            # Assert

            self.assertEqual(result.exit_code, 0)
            self.assertIn("Comparison Results:", result.stdout)
            # Verify both notification functions were called

            mock_slack.assert_called_once()
            mock_teams.assert_called_once()

    @patch("chimera_intel.core.differ.get_last_two_scans")
    @patch("chimera_intel.core.differ.send_teams_notification")
    @patch("chimera_intel.core.differ.send_slack_notification")
    def test_cli_diff_command_no_notification_urls(
        self, mock_slack, mock_teams, mock_get_scans
    ):
        """Tests that no notifications are sent if webhooks are not configured."""
        # Arrange: Mock the data and ensure API keys are None

        mock_get_scans.return_value = ({"key": "new"}, {"key": "old"})
        with patch("chimera_intel.core.differ.API_KEYS") as mock_keys:
            mock_keys.slack_webhook_url = None
            mock_keys.teams_webhook_url = None

            # Act

            runner.invoke(app, ["analysis", "diff", "run", "footprint", "example.com"])

            # Assert: Verify no notification functions were called

            mock_slack.assert_not_called()
            mock_teams.assert_not_called()

    @patch("chimera_intel.core.differ.get_last_two_scans")
    def test_cli_diff_command_no_changes(self, mock_get_scans):
        """Tests the `analysis diff run` command when no changes are detected."""
        # Arrange

        mock_get_scans.return_value = ({"key": "value"}, {"key": "value"})

        # Act

        result = runner.invoke(
            app, ["analysis", "diff", "run", "footprint", "example.com"]
        )

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("Comparison Results:", result.stdout)

    @patch("chimera_intel.core.differ.get_last_two_scans")
    def test_cli_diff_command_not_enough_data(self, mock_get_scans):
        """Tests the CLI command's graceful exit when not enough historical data is found."""
        # Arrange

        mock_get_scans.return_value = (None, None)

        # Act

        result = runner.invoke(
            app, ["analysis", "diff", "run", "footprint", "example.com"]
        )

        # Assert: The command should exit with a non-zero code to indicate an issue.

        self.assertEqual(result.exit_code, 0)  # Typer's Exit() defaults to 0
        self.assertNotIn("Comparison Results:", result.stdout)

    # --- NEW: Project-Aware CLI Tests ---

    @patch("chimera_intel.core.differ.get_active_project")
    @patch("chimera_intel.core.differ.get_last_two_scans")
    def test_cli_diff_command_with_project(self, mock_get_scans, mock_get_project):
        """Tests the CLI command using an active project's context."""
        # Arrange

        mock_project = ProjectConfig(
            project_name="DiffTest",
            created_at="2025-01-01",
            domain="project-diff.com",
        )
        mock_get_project.return_value = mock_project
        # Simulate finding changes to trigger output

        mock_get_scans.return_value = ({"key": "new"}, {"key": "old"})

        # Act: Run command without an explicit target

        result = runner.invoke(app, ["analysis", "diff", "run", "footprint"])

        # Assert

        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Using target 'project-diff.com' from active project", result.stdout
        )
        # Verify get_last_two_scans was called with the project's domain

        mock_get_scans.assert_called_with("project-diff.com", "footprint")

    @patch("chimera_intel.core.differ.get_active_project")
    def test_cli_diff_command_no_target_no_project(self, mock_get_project):
        """Tests CLI failure when no target is given and no project is active."""
        # Arrange

        mock_get_project.return_value = None

        # Act

        result = runner.invoke(app, ["analysis", "diff", "run", "footprint"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("No target provided and no active project set", result.stdout)


if __name__ == "__main__":
    unittest.main()
