import unittest
from unittest.mock import patch
from chimera_intel.core.differ import get_last_two_scans, format_diff_simple
from chimera_intel.core.schemas import FormattedDiff

# FIX: Remove unused imports as they are handled within the source function

from jsondiff import diff


class TestDiffer(unittest.TestCase):
    """Test cases for the differ module."""

    @patch("chimera_intel.core.differ.sqlite3.connect")
    def test_get_last_two_scans_success(self, mock_connect):
        """Tests retrieving the last two scans from the database."""
        mock_cursor = mock_connect.return_value.cursor.return_value
        scan1 = '{"subdomains": ["a.com"]}'
        scan2 = '{"subdomains": ["b.com"]}'
        mock_cursor.fetchall.return_value = [(scan1,), (scan2,)]

        latest, previous = get_last_two_scans("example.com", "footprint")

        self.assertIsNotNone(latest)
        self.assertIsNotNone(previous)
        self.assertEqual(latest["subdomains"][0], "a.com")
        self.assertEqual(previous["subdomains"][0], "b.com")

    @patch("chimera_intel.core.differ.sqlite3.connect")
    def test_get_last_two_scans_not_enough_data(self, mock_connect):
        """Tests retrieval when there are fewer than two scans."""
        mock_cursor = mock_connect.return_value.cursor.return_value
        mock_cursor.fetchall.return_value = [('{"key": "value"}',)]  # Only one record

        latest, previous = get_last_two_scans("example.com", "footprint")
        self.assertIsNone(latest)
        self.assertIsNone(previous)

    @patch("chimera_intel.core.differ.sqlite3.connect")
    def test_get_last_two_scans_db_error(self, mock_connect):
        """Tests retrieval when a database error occurs."""
        mock_connect.side_effect = Exception("DB Error")
        latest, previous = get_last_two_scans("example.com", "footprint")
        self.assertIsNone(latest)
        self.assertIsNone(previous)

    def test_format_diff_simple(self):
        """Tests the simplification of a jsondiff result."""
        old_scan = {"tech": ["React"], "ports": [80], "users": {"admin": True}}
        new_scan = {"tech": ["Vue"], "ports": [80], "users": {}}

        raw_diff = diff(old_scan, new_scan, syntax="symmetric")
        formatted = format_diff_simple(raw_diff)

        self.assertIsInstance(formatted, FormattedDiff)
        # Check for the change in the 'tech' list

        self.assertIn("tech: ['React']", formatted.removed)
        self.assertIn("tech: ['Vue']", formatted.added)
        # Check for the removal of the 'admin' user

        self.assertIn("users.admin", formatted.removed)


if __name__ == "__main__":
    unittest.main()
