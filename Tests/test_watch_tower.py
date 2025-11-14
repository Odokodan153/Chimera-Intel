import unittest
from unittest.mock import patch, MagicMock
import json

from chimera_intel.core.watch_tower import monitor_page_for_changes, _get_baseline_data
from chimera_intel.core.schemas import PageMonitorConfig

class TestWatchTower(unittest.TestCase):
    """Test cases for the new OSINT Watch Tower module."""

    @patch("chimera_intel.core.watch_tower.get_db_connection")
    def test_get_baseline_data(self, mock_get_conn):
        """Tests retrieving baseline data from the database."""
        # Arrange
        watch_id = "test-watch-id"
        mock_data = json.dumps({
            "all_text_snippets": ["old text"],
            "all_links": ["http://old.link"]
        })
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (mock_data,)
        mock_conn.cursor.return_value = __enter__=MagicMock(return_value=mock_cursor)
        mock_get_conn.return_value = mock_conn

        # Act
        snippets, links = _get_baseline_data(watch_id)

        # Assert
        mock_cursor.execute.assert_called_with(
            unittest.mock.ANY, # SQL query
            (watch_id, "watch_tower")
        )
        self.assertEqual(snippets, {"old text"})
        self.assertEqual(links, {"http://old.link"})

    @patch("chimera_intel.core.watch_tower._get_baseline_data")
    @patch("chimera_intel.core.watch_tower._fetch_and_parse_page")
    @patch("chimera_intel.core.watch_tower._save_baseline_data")
    @patch("chimera_intel.core.watch_tower.alert_manager_instance.dispatch_alert")
    def test_monitor_finds_new_keyword(
        self, mock_dispatch_alert, mock_save_baseline, mock_fetch_page, mock_get_baseline
    ):
        """Tests that a new text snippet containing a keyword triggers an alert."""
        # Arrange
        watch_config = PageMonitorConfig(
            url="http://example.com/careers",
            keywords=["GCP", "Snowflake"]
        )
        
        # 1. Baseline: Return old data
        mock_get_baseline.return_value = (
            {"Job: Data Analyst", "Location: New York"}, # old text
            {"http://example.com/apply"} # old links
        )
        
        # 2. Fetch: Return new data
        new_text = {
            "Job: Data Analyst", 
            "Location: New York", 
            "Job: Cloud Engineer (GCP)", # <-- New job
            "We use Snowflake" # <-- New keyword
        }
        new_links = {"http://example.com/apply", "http://example.com/new-role"}
        mock_fetch_page.return_value = (new_text, new_links)

        # Act
        monitor_page_for_changes(watch_config)

        # Assert
        # 1. Check that an alert was dispatched
        mock_dispatch_alert.assert_called_once()
        alert_args = mock_dispatch_alert.call_args[1]
        
        self.assertEqual(alert_args['title'], f"Keyword Alert: {watch_config.url}")
        self.assertEqual(alert_args['level'], "WARNING")
        self.assertIn("gcp: Job: Cloud Engineer (GCP)", alert_args['message'])
        self.assertIn("snowflake: We use Snowflake", alert_args['message'])
        
        # 2. Check that the new baseline was saved
        mock_save_baseline.assert_called_once_with(
            watch_config.watch_id, new_text, new_links
        )

    @patch("chimera_intel.core.watch_tower._get_baseline_data")
    @patch("chimera_intel.core.watch_tower._fetch_and_parse_page")
    @patch("chimera_intel.core.watch_tower._save_baseline_data")
    @patch("chimera_intel.core.watch_tower.alert_manager_instance.dispatch_alert")
    def test_monitor_no_changes(
        self, mock_dispatch_alert, mock_save_baseline, mock_fetch_page, mock_get_baseline
    ):
        """Tests that no alerts are sent when no text has changed."""
        # Arrange
        watch_config = PageMonitorConfig(
            url="http://example.com/careers",
            keywords=["GCP"]
        )
        
        old_text = {"Job: Data Analyst", "Location: New York"}
        old_links = {"http://example.com/apply"}
        
        # 1. Baseline: Return old data
        mock_get_baseline.return_value = (old_text, old_links)
        
        # 2. Fetch: Return the *same* data
        mock_fetch_page.return_value = (old_text, old_links)

        # Act
        monitor_page_for_changes(watch_config)

        # Assert
        # 1. No alert
        mock_dispatch_alert.assert_not_called()
        
        # 2. Baseline is still saved (to refresh timestamps, etc.)
        mock_save_baseline.assert_called_once_with(
            watch_config.watch_id, old_text, old_links
        )

if __name__ == "__main__":
    unittest.main()