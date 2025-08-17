import unittest
import sqlite3
import os
from unittest.mock import patch, MagicMock
from chimera_intel.core.database import (
    initialize_database,
    save_scan_to_db,
    get_aggregated_data_for_target,
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
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans';")
        self.assertIsNotNone(cursor.fetchone())
        conn.close()

    @patch("sqlite3.connect")
    def test_initialize_database_sqlite_error(self, mock_connect):
        """Tests initialization when a database error occurs."""
        mock_connect.side_effect = sqlite3.Error("Test error")
        # The function should catch the error and not crash
        initialize_database()

    def test_save_and_get_scan(self):
        """Tests saving and retrieving a scan."""
        test_data = {"key": "value"}
        save_scan_to_db("example.com", "footprint", test_data)

        # Use a real db connection to verify the data was saved
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT target, module, scan_data FROM scans")
        row = cursor.fetchone()
        self.assertEqual(row[0], "example.com")
        self.assertEqual(row[1], "footprint")
        self.assertIn('"key": "value"', row[2])
        conn.close()

    def test_get_aggregated_data_for_target(self):
        """Tests aggregation of multiple module scans for a target."""
        save_scan_to_db("example.com", "footprint", {"footprint_key": "v1"})
        save_scan_to_db("example.com", "web_analyzer", {"web_key": "v2"})
        # Save an older scan to ensure only the latest is picked
        save_scan_to_db("example.com", "footprint", {"footprint_key": "v0"})


        aggregated = get_aggregated_data_for_target("example.com")
        self.assertIsNotNone(aggregated)
        self.assertIn("footprint", aggregated["modules"])
        self.assertIn("web_analyzer", aggregated["modules"])
        self.assertEqual(aggregated["modules"]["footprint"]["footprint_key"], "v1")

    def test_get_aggregated_data_no_data(self):
        """Tests aggregation when no data exists for the target."""
        aggregated = get_aggregated_data_for_target("nonexistent.com")
        self.assertIsNone(aggregated)


if __name__ == '__main__':
    unittest.main()