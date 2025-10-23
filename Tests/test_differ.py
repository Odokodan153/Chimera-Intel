import unittest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import typer  
from jsondiff import insert
from chimera_intel.core.differ import diff_app


runner = CliRunner()

app = typer.Typer()
app.add_typer(diff_app, name="diff")


class TestDiffer(unittest.TestCase):
    """Test cases for the differ module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.differ.get_db_connection")
    def test_get_last_two_scans_success(self, mock_get_conn):
        """Tests retrieving the last two scans successfully."""
        # Arrange
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ({"key": "new_value"},),
            ({"key": "old_value"},),
        ]
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        from chimera_intel.core.differ import get_last_two_scans

        # Act
        latest, previous = get_last_two_scans("example.com", "footprint")

        # Assert
        self.assertEqual(latest, {"key": "new_value"})
        self.assertEqual(previous, {"key": "old_value"})

    @patch("chimera_intel.core.differ.get_db_connection")
    def test_get_last_two_scans_not_enough_data(self, mock_get_conn):
        """Tests the case where there are fewer than two scans."""
        # Arrange
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [({"key": "new_value"},)]
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        from chimera_intel.core.differ import get_last_two_scans

        # Act
        latest, previous = get_last_two_scans("example.com", "footprint")

        # Assert
        self.assertIsNone(latest)
        self.assertIsNone(previous)

    def test_format_diff_simple(self):
        """Tests the simplified diff formatting."""
        # Arrange
        previous = {"a": 1, "b": {"c": 2}}
        latest = {"a": 1, "b": {"c": 3}, "d": 4}

        from chimera_intel.core.differ import format_diff_simple

        # Act
        diff = format_diff_simple(previous, latest)

        # Assert
        self.assertIn("d", diff.added)
        self.assertIn("b.c: 2", diff.removed)
        self.assertIn("b.c: 3", diff.added)

    def test_analyze_diff_for_signals(self):
        """Tests the signal analysis from a raw diff."""
        # Arrange
        raw_diff = {"footprint": {"dns_records": {"A": {insert: ["1.2.3.4"]}}}}
        from chimera_intel.core.differ import analyze_diff_for_signals

        # Act
        signals = analyze_diff_for_signals(raw_diff)

        # Assert
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].signal_type, "Infrastructure Change")
        self.assertIn("1.2.3.4", signals[0].description)

    # --- CLI Tests ---

    @patch("chimera_intel.core.differ.resolve_target", return_value="example.com")
    @patch("chimera_intel.core.differ.get_last_two_scans")
    @patch("chimera_intel.core.differ.send_slack_notification")
    def test_cli_diff_run_with_changes(self, mock_slack, mock_get_scans, mock_resolve):
        """Tests the 'diff run' command when changes are detected."""
        # Arrange
        mock_get_scans.return_value = (
            {"footprint": {"dns_records": {"A": ["1.1.1.1", "2.2.2.2"]}}},
            {"footprint": {"dns_records": {"A": ["1.1.1.1"]}}},
        )
        
        # --- FIX APPLIED ---
        # Patch BOTH webhook URLs so the 'if' checks in the main code pass.
        # Also patch the notification functions themselves and the console.
        with patch("chimera_intel.core.differ.API_KEYS.slack_webhook_url", "fake_slack_url"), \
             patch("chimera_intel.core.differ.API_KEYS.teams_webhook_url", "fake_teams_url"), \
             patch("chimera_intel.core.differ.send_teams_notification") as mock_teams, \
             patch("chimera_intel.core.differ.console.print") as mock_console:
            
            # Act
            result = runner.invoke(
                app, ["diff", "run", "footprint", "--target", "example.com"]
            )
        # --- END FIX ---

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        
        # Check console output via the mock's call arguments
        console_output = " ".join([call.args[0] for call in mock_console.call_args_list if call.args])
        self.assertIn("Comparison Results", console_output)
        self.assertIn("footprint.dns_records.A.1", console_output)
        self.assertIn("Added: 2.2.2.2", console_output)

        # Verify notifications were called
        mock_slack.assert_called_once()
        mock_teams.assert_called_once()

        # Optional: Check *what* they were called with
        self.assertIn("Change Detected", mock_slack.call_args[0][1])
        self.assertIn("Added: 2.2.2.2", mock_teams.call_args[0][2])


    @patch("chimera_intel.core.differ.resolve_target", return_value="example.com")
    @patch("chimera_intel.core.differ.get_last_two_scans")
    def test_cli_diff_run_no_changes(self, mock_get_scans, mock_resolve):
        """Tests the 'diff run' command when no changes are detected."""
        # Arrange
        mock_get_scans.return_value = ({"a": 1}, {"a": 1})

        # Act
        result = runner.invoke(
            app, ["diff", "run", "footprint", "--target", "example.com"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("No changes detected", result.stdout)

    @patch("chimera_intel.core.differ.resolve_target", return_value="example.com")
    @patch("chimera_intel.core.differ.get_last_two_scans")
    def test_cli_diff_run_not_enough_data(self, mock_get_scans, mock_resolve):
        """Tests the 'diff run' command when there aren't enough scans to compare."""
        # Arrange
        mock_get_scans.return_value = (None, None)

        # Act
        result = runner.invoke(
            app, ["diff", "run", "footprint", "--target", "example.com"]
        )

        # Assert
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Not enough historical data", result.stdout)


if __name__ == "__main__":
    unittest.main()