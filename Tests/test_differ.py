import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import typer
from jsondiff import insert

from chimera_intel.core.differ import (
    get_last_two_scans,
    _flatten_dict,
    format_diff_simple,
    analyze_diff_for_signals,
    diff_app,
)
from chimera_intel.core.schemas import FormattedDiff, MicroSignal

runner = CliRunner(mix_stderr=False)


class TestDiffer(unittest.TestCase):
    """Test cases for the differ module."""

    @patch("chimera_intel.core.differ.get_db_connection")
    def test_get_last_two_scans_success(self, mock_get_conn):
        """Tests retrieving the last two scans successfully."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [
            ({"version": 2},),
            ({"version": 1},),
        ]

        latest, previous = get_last_two_scans("example.com", "footprint")

        self.assertEqual(latest, {"version": 2})
        self.assertEqual(previous, {"version": 1})

    @patch("chimera_intel.core.differ.get_db_connection")
    def test_get_last_two_scans_insufficient_data(self, mock_get_conn):
        """Tests retrieving scans when there is less than two."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [({"version": 1},)]

        latest, previous = get_last_two_scans("example.com", "footprint")

        self.assertIsNone(latest)
        self.assertIsNone(previous)

    @patch("chimera_intel.core.differ.get_db_connection")
    def test_get_last_two_scans_db_error(self, mock_get_conn):
        """Tests database error during scan retrieval."""
        mock_get_conn.side_effect = Exception("DB connection failed")

        latest, previous = get_last_two_scans("example.com", "footprint")

        self.assertIsNone(latest)
        self.assertIsNone(previous)

    def test_flatten_dict(self):
        """Tests the dictionary flattening utility."""
        nested_dict = {
            "a": 1,
            "b": {"c": 2},
            "d": [{"domain": "sub.example.com"}, {"id": "tech"}],
        }
        flat_dict = _flatten_dict(nested_dict)
        self.assertEqual(flat_dict["a"], 1)
        self.assertEqual(flat_dict["b.c"], 2)
        self.assertIn("d.sub.example.com.domain", flat_dict)
        self.assertIn("d.tech.id", flat_dict)

    def test_format_diff_simple(self):
        """Tests the simple diff formatting."""
        previous_scan = {"a": 1, "b": {"c": 2}, "e": 5}
        latest_scan = {"a": 1, "b": {"c": 3}, "d": 4}

        diff = format_diff_simple(previous_scan, latest_scan)

        self.assertIsInstance(diff, FormattedDiff)
        self.assertIn("d", diff.added)
        self.assertIn("e", diff.removed)
        self.assertIn("b.c: 2", diff.removed)
        self.assertIn("b.c: 3", diff.added)

    def test_analyze_diff_for_signals(self):
        """Tests signal analysis from a raw diff."""
        diff_result = {
            "footprint": {"dns_records": {"A": {insert: ["1.2.3.4", "5.6.7.8"]}}}
        }
        signals = analyze_diff_for_signals(diff_result)
        self.assertEqual(len(signals), 1)
        self.assertIsInstance(signals[0], MicroSignal)
        self.assertEqual(signals[0].signal_type, "Infrastructure Change")
        self.assertIn("1.2.3.4", signals[0].description)

    @patch("chimera_intel.core.differ.resolve_target", return_value="example.com")
    @patch("chimera_intel.core.differ.get_last_two_scans")
    @patch("chimera_intel.core.differ.send_slack_notification")
    @patch("chimera_intel.core.differ.send_teams_notification")
    @patch("chimera_intel.core.differ.API_KEYS")
    def test_cli_run_diff_analysis_with_changes_and_notifications(
        self, mock_api_keys, mock_teams, mock_slack, mock_get_scans, mock_resolve
    ):
        """Tests the CLI command with changes and notifications triggered."""
        mock_api_keys.slack_webhook_url = "http://fake.slack.url"
        mock_api_keys.teams_webhook_url = "http://fake.teams.url"
        mock_get_scans.return_value = ({"a": 2}, {"a": 1})

        result = runner.invoke(diff_app, ["footprint"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Comparison Results", result.stdout)
        mock_slack.assert_called_once()
        mock_teams.assert_called_once()

    @patch("chimera_intel.core.differ.resolve_target", return_value="example.com")
    @patch("chimera_intel.core.differ.get_last_two_scans")
    def test_cli_run_diff_analysis_no_changes(self, mock_get_scans, mock_resolve):
        """Tests the CLI command when no changes are detected."""
        mock_get_scans.return_value = ({"a": 1}, {"a": 1})

        result = runner.invoke(diff_app, ["footprint"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("No changes detected", result.stdout)

    @patch("chimera_intel.core.differ.resolve_target", return_value="example.com")
    @patch("chimera_intel.core.differ.get_last_two_scans", return_value=(None, None))
    def test_cli_run_diff_analysis_insufficient_data(
        self, mock_get_scans, mock_resolve
    ):
        """Tests the CLI command with insufficient historical data."""
        result = runner.invoke(diff_app, ["footprint"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Not enough historical data", result.stdout)

    @patch("chimera_intel.core.differ.resolve_target")
    @patch("chimera_intel.core.differ.get_last_two_scans", return_value=({}, {}))
    def test_cli_run_diff_with_project(self, mock_get_scans, mock_resolve_target):
        """Tests the CLI command using an active project's context."""
        mock_resolve_target.return_value = "project.com"

        result = runner.invoke(diff_app, ["footprint"])

        self.assertEqual(result.exit_code, 0)
        mock_resolve_target.assert_called_with(None, required_assets=["domain"])
        mock_get_scans.assert_called_with("project.com", "footprint")

    @patch("chimera_intel.core.differ.resolve_target")
    def test_cli_run_diff_no_target_no_project(self, mock_resolve_target):
        """Tests CLI failure when no target is provided and no project is active."""
        mock_resolve_target.side_effect = typer.Exit(1)
        result = runner.invoke(diff_app, ["footprint"])
        self.assertEqual(result.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
