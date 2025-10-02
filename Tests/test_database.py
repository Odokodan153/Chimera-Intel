import unittest
import datetime
import json
from unittest.mock import patch, MagicMock
from chimera_intel.core.database import (
    initialize_database,
    save_scan_to_db,
    get_aggregated_data_for_target,
    get_scan_history,
    get_all_scans_for_target,
    create_user_in_db,
    get_user_from_db,
)
from chimera_intel.core.schemas import User
import psycopg2


class TestDatabase(unittest.TestCase):
    """Test cases for PostgreSQL database functions."""

    @patch("chimera_intel.core.database.get_db_connection")
    def test_initialize_database(self, mock_get_conn):
        """Tests if the database and tables are created."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        initialize_database()

        # Check that the connection was opened and closed
        mock_get_conn.assert_called_once()
        self.assertTrue(mock_cursor.execute.called)
        self.assertTrue(mock_conn.commit.called)
        self.assertTrue(mock_cursor.close.called)
        self.assertTrue(mock_conn.close.called)

    @patch("chimera_intel.core.database.get_db_connection")
    def test_initialize_database_psycopg2_error(self, mock_get_conn):
        """Tests initialization when a database error occurs."""
        mock_get_conn.side_effect = psycopg2.Error("Test connection error")
        with patch("rich.console.Console.print") as mock_print:
            initialize_database()
            mock_print.assert_called()

    @patch("chimera_intel.core.database.get_db_connection")
    def test_create_and_get_user(self, mock_get_conn):
        """Tests creating a new user and retrieving them from the database."""
        # Mock for create_user_in_db
        mock_conn_create = MagicMock()
        mock_cursor_create = MagicMock()
        mock_get_conn.return_value = mock_conn_create
        mock_conn_create.cursor.return_value = mock_cursor_create

        create_user_in_db("testuser", "hashed_password")

        # Mock for get_user_from_db
        mock_conn_get = MagicMock()
        mock_cursor_get = MagicMock()
        mock_get_conn.return_value = mock_conn_get
        mock_conn_get.cursor.return_value = mock_cursor_get
        mock_cursor_get.fetchone.return_value = (1, "testuser", "hashed_password")

        user = get_user_from_db("testuser")

        self.assertIsNotNone(user)
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, "testuser")

    @patch("chimera_intel.core.database.get_db_connection")
    def test_save_and_get_scan_with_user(self, mock_get_conn):
        """Tests saving a scan with a user_id and retrieving it."""
        test_data = {"key": "value"}
        user_id = 1

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        save_scan_to_db("example.com", "footprint", test_data, user_id=user_id)

        # Verify the INSERT call
        mock_cursor.execute.assert_called_with(
            "INSERT INTO scans (target, module, scan_data, user_id, project_id) VALUES (%s, %s, %s, %s, %s)",
            (
                "example.com",
                "footprint",
                json.dumps(test_data, indent=4, default=str),
                user_id,
                None,
            ),
        )

    @patch("chimera_intel.core.database.get_db_connection")
    def test_save_scan_to_db_error(self, mock_get_conn):
        """Tests saving to db when a database error occurs."""
        mock_get_conn.side_effect = psycopg2.Error("Cannot write to db")
        with patch("rich.console.Console.print") as mock_print:
            save_scan_to_db("example.com", "footprint", {})
            mock_print.assert_called()

    @patch("chimera_intel.core.database.get_db_connection")
    def test_get_aggregated_data_for_target(self, mock_get_conn):
        """Tests aggregation of multiple module scans for a target."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        # Simulate fetching footprint and web_analyzer data
        mock_cursor.fetchone.side_effect = [
            ({"footprint_key": "v1"},),  # For footprint
            ({"web_key": "v2"},),  # For web_analyzer
            None,  # For all other modules
        ] * 12  # Repeat None for the rest of the modules

        aggregated = get_aggregated_data_for_target("example.com")
        self.assertIsNotNone(aggregated)
        self.assertIn("footprint", aggregated["modules"])
        self.assertIn("web_analyzer", aggregated["modules"])
        self.assertEqual(aggregated["modules"]["footprint"]["footprint_key"], "v1")

    @patch("chimera_intel.core.database.get_db_connection")
    def test_get_aggregated_data_no_data(self, mock_get_conn):
        """Tests aggregation when no data exists for the target."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None  # No records found

        aggregated = get_aggregated_data_for_target("nonexistent.com")
        self.assertIsNone(aggregated)

    @patch("chimera_intel.core.database.get_db_connection")
    def test_get_scan_history(self, mock_get_conn):
        """Tests retrieving the full scan history."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        now = datetime.datetime.now()
        mock_cursor.fetchall.return_value = [
            (3, "example.com", "business_intel", now, "{}"),
            (
                2,
                "google.com",
                "web_analyzer",
                now - datetime.timedelta(seconds=1),
                "{}",
            ),
            (1, "example.com", "footprint", now - datetime.timedelta(seconds=2), "{}"),
        ]

        history = get_scan_history()
        self.assertIsInstance(history, list)
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0]["target"], "example.com")
        self.assertEqual(history[0]["module"], "business_intel")

    @patch("chimera_intel.core.database.get_db_connection")
    def test_get_all_scans_for_target(self, mock_get_conn):
        """Tests retrieving all scans for a target, ordered chronologically."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_conn.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        now = datetime.datetime.now()
        # FIX: Return a dict instead of a JSON string to correctly mock psycopg2's JSONB deserialization
        mock_cursor.fetchall.return_value = [
            ({"step": 1}, now),
            ({"step": 2}, now + datetime.timedelta(seconds=1)),
        ]

        history = get_all_scans_for_target("target-a.com")
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["scan_data"], {"step": 1})
        self.assertEqual(history[1]["scan_data"], {"step": 2})


if __name__ == "__main__":
    unittest.main()