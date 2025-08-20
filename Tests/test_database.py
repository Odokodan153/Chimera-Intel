import unittest
import sqlite3
import os
import datetime
from unittest.mock import patch
from chimera_intel.core.database import (
    initialize_database,
    save_scan_to_db,
    get_aggregated_data_for_target,
    get_scan_history,  # Import the new function
    DB_FILE,
)


class TestDatabase(unittest.TestCase):
    """Test cases for database functions."""

    def setUp(self):
        """Set up a clean database for each test."""
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        initialize_database()

    def tearDown(self):
        """Remove the database file after each test."""
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

    def test_initialize_database(self):
        """Tests if the database and table are created."""
        self.assertTrue(os.path.exists(DB_FILE))
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scans';"
        )
        self.assertIsNotNone(cursor.fetchone())
        conn.close()

    @patch("sqlite3.connect")
    def test_initialize_database_sqlite_error(self, mock_connect):
        """Tests initialization when a database error occurs."""
        mock_connect.side_effect = sqlite3.Error("Test error")
        # The function should catch the error and not crash

        with patch("rich.console.Console.print") as mock_print:
            initialize_database()
            mock_print.assert_called()

    def test_save_and_get_scan(self):
        """Tests saving and retrieving a scan."""
        test_data = {"key": "value"}
        save_scan_to_db("example.com", "footprint", test_data)

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT target, module, scan_data FROM scans")
        row = cursor.fetchone()
        self.assertEqual(row[0], "example.com")
        self.assertEqual(row[1], "footprint")
        self.assertIn('"key": "value"', row[2])
        conn.close()

    @patch("sqlite3.connect")
    def test_save_scan_to_db_error(self, mock_connect):
        """Tests saving to db when a database error occurs."""
        mock_connect.side_effect = sqlite3.Error("Cannot write to db")
        with patch("rich.console.Console.print") as mock_print:
            save_scan_to_db("example.com", "footprint", {})
            mock_print.assert_called()

    @patch("chimera_intel.core.database.datetime")
    def test_get_aggregated_data_for_target(self, mock_datetime):
        """Tests aggregation of multiple module scans for a target."""
        base_time = datetime.datetime.now()

        # First scan

        mock_datetime.datetime.now.return_value.isoformat.return_value = (
            base_time.isoformat()
        )
        save_scan_to_db("example.com", "footprint", {"footprint_key": "v0"})

        # Second scan - simulate 1 second later

        mock_datetime.datetime.now.return_value.isoformat.return_value = (
            base_time + datetime.timedelta(seconds=1)
        ).isoformat()
        save_scan_to_db("example.com", "web_analyzer", {"web_key": "v2"})

        # Third scan - simulate 2 seconds later (this is now the latest)

        mock_datetime.datetime.now.return_value.isoformat.return_value = (
            base_time + datetime.timedelta(seconds=2)
        ).isoformat()
        save_scan_to_db("example.com", "footprint", {"footprint_key": "v1"})

        aggregated = get_aggregated_data_for_target("example.com")
        self.assertIsNotNone(aggregated)
        self.assertIn("footprint", aggregated["modules"])
        self.assertIn("web_analyzer", aggregated["modules"])
        # The test will now correctly and reliably check for the latest record, 'v1'

        self.assertEqual(aggregated["modules"]["footprint"]["footprint_key"], "v1")

    def test_get_aggregated_data_no_data(self):
        """Tests aggregation when no data exists for the target."""
        aggregated = get_aggregated_data_for_target("nonexistent.com")
        self.assertIsNone(aggregated)

    @patch("sqlite3.connect")
    def test_get_aggregated_data_error(self, mock_connect):
        """Tests aggregation when a database error occurs."""
        mock_connect.side_effect = sqlite3.Error("Cannot read from db")
        result = get_aggregated_data_for_target("example.com")
        self.assertIsNone(result)

    def test_get_scan_history(self):
        """Tests retrieving the full scan history."""
        # Save some dummy scans

        save_scan_to_db("example.com", "footprint", {"data": 1})
        save_scan_to_db("google.com", "web_analyzer", {"data": 2})
        save_scan_to_db("example.com", "business_intel", {"data": 3})

        history = get_scan_history()

        self.assertIsInstance(history, list)
        self.assertEqual(len(history), 3)
        # Check if the most recent scan is first (business_intel)

        self.assertEqual(history[0]["target"], "example.com")
        self.assertEqual(history[0]["module"], "business_intel")
        # Check the oldest scan is last (footprint)

        self.assertEqual(history[2]["target"], "example.com")
        self.assertEqual(history[2]["module"], "footprint")


if __name__ == "__main__":
    unittest.main()
