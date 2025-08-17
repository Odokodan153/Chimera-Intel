import unittest
from unittest.mock import patch, mock_open, MagicMock
from chimera_intel.core.utils import (
    save_or_print_results,
    is_valid_domain,
    send_slack_notification,
)


class TestUtils(unittest.TestCase):
    """Tests for utility functions in utils.py."""

    def test_is_valid_domain(self):
        """Tests the domain validation."""
        self.assertTrue(is_valid_domain("google.com"))
        self.assertFalse(is_valid_domain("not a domain"))
        self.assertFalse(is_valid_domain("google..com"))

    @patch("builtins.open", new_callable=mock_open)
    def test_save_or_print_results_saves_to_file(self, mock_file):
        """Tests if the function saves to a file when a path is provided."""
        data = {"key": "value"}
        output_file = "test.json"

        with patch("rich.console.Console.print") as mock_print:
            save_or_print_results(data, output_file)

            # Check if the file was opened for writing

            mock_file.assert_called_once_with(output_file, "w", encoding="utf-8")
            # Check if the data was written to the file

            mock_file().write.assert_called_once_with('{\n    "key": "value"\n}')
            # Check that it doesn't print to the console (except for the success message)

            mock_print.assert_any_call(
                f"[bold green]Successfully saved to {output_file}[/bold green]"
            )

    def test_save_or_print_results_prints_to_console(self):
        """Tests if the function prints to the console when no file is provided."""
        data = {"key": "value"}

        with patch("rich.console.Console.print") as mock_print:
            save_or_print_results(data, None)
            # Check that the print function was called

            self.assertTrue(mock_print.called)
            # Check that it was not called with a success message

            with self.assertRaises(AssertionError):
                mock_print.assert_any_call(
                    "[bold green]Successfully saved to ...[/bold green]"
                )

    @patch("chimera_intel.core.http_client.sync_client.post")
    def test_send_slack_notification_success(self, mock_post):
        """Tests a successful Slack notification dispatch."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        send_slack_notification("http://fake.webhook.url", "Test message")
        mock_post.assert_called_once()

    @patch("chimera_intel.core.http_client.sync_client.post")
    def test_send_slack_notification_failure(self, mock_post):
        """Tests a failed Slack notification dispatch."""
        # Simulate an error (e.g., wrong URL)

        mock_post.side_effect = Exception("Network Error")

        # Check that the function doesn't crash but just logs an error (we can't easily test logs here)

        send_slack_notification("http://fake.webhook.url", "Test message")
        mock_post.assert_called_once()
