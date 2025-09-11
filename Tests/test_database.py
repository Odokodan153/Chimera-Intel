import unittest
import sqlite3
import os
import datetime
import json
from unittest.mock import patch
from chimera_intel.core.database import (
    initialize_database,
    save_scan_to_db,
    get_aggregated_data_for_target,
    get_scan_history,
    get_scan_history_for_target,  # New import
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
        with patch("rich.console.Console.print") as mock_print:
            initialize_database()
            mock_print.assert_called()

    @patch("chimera_intel.core.database.correlation_engine.run_correlations")
    def test_save_and_get_scan(self, mock_run_correlations):
        """Tests saving and retrieving a scan, ensuring the correlation engine is called."""
        test_data = {"key": "value"}
        save_scan_to_db("example.com", "footprint", test_data)

        # Verify the data was saved correctly

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT target, module, scan_data FROM scans")
        row = cursor.fetchone()
        self.assertEqual(row[0], "example.com")
        self.assertEqual(row[1], "footprint")
        self.assertIn('"key": "value"', row[2])
        conn.close()

        # Verify the correlation engine was triggered

        mock_run_correlations.assert_called_once_with(
            "example.com", "footprint", test_data
        )

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
        mock_datetime.datetime.now.return_value.isoformat.return_value = (
            base_time.isoformat()
        )
        save_scan_to_db("example.com", "footprint", {"footprint_key": "v0"})
        mock_datetime.datetime.now.return_value.isoformat.return_value = (
            base_time + datetime.timedelta(seconds=1)
        ).isoformat()
        save_scan_to_db("example.com", "web_analyzer", {"web_key": "v2"})
        mock_datetime.datetime.now.return_value.isoformat.return_value = (
            base_time + datetime.timedelta(seconds=2)
        ).isoformat()
        save_scan_to_db("example.com", "footprint", {"footprint_key": "v1"})

        aggregated = get_aggregated_data_for_target("example.com")
        self.assertIsNotNone(aggregated)
        self.assertIn("footprint", aggregated["modules"])
        self.assertIn("web_analyzer", aggregated["modules"])
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
        save_scan_to_db("example.com", "footprint", {"data": 1})
        save_scan_to_db("google.com", "web_analyzer", {"data": 2})
        save_scan_to_db("example.com", "business_intel", {"data": 3})

        history = get_scan_history()
        self.assertIsInstance(history, list)
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0]["target"], "example.com")
        self.assertEqual(history[0]["module"], "business_intel")
        self.assertEqual(history[2]["target"], "example.com")
        self.assertEqual(history[2]["module"], "footprint")

    # --- NEW TEST CASE ---

    def test_get_scan_history_for_target(self):
        """Tests retrieving scan history filtered for a specific target."""
        # Save scans for two different targets

        save_scan_to_db("target-a.com", "footprint", {"data": "A1"})
        save_scan_to_db("target-b.com", "web_analyzer", {"data": "B1"})
        save_scan_to_db("target-a.com", "business_intel", {"data": "A2"})

        # Retrieve history for only target-a.com

        history = get_scan_history_for_target("target-a.com")

        self.assertIsInstance(history, list)
        self.assertEqual(len(history), 2)
        # Verify that all returned records belong to the correct target

        self.assertTrue(all(item["target"] == "target-a.com" for item in history))
        # Verify that the most recent scan for target-a.com is first

        self.assertEqual(history[0]["module"], "business_intel")


if __name__ == "__main__":
    unittest.main()
