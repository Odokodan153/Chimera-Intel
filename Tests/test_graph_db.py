import unittest
import json
from unittest.mock import patch
from chimera_intel.core.graph_db import build_and_save_graph


class TestGraphDb(unittest.TestCase):
    """Test cases for the Graph Database module."""

    @patch("chimera_intel.core.graph_db.get_db_connection")  # Mock the save operation
    @patch(
        "chimera_intel.core.graph_db.get_all_scans_for_target"
    )  # Mock the read operation
    def test_build_and_save_graph(self, mock_get_scans, mock_get_conn):
        """Tests building and saving a graph from scan data."""
        # Arrange: Provide mock scan data from the database

        scan_data = {
            "footprint": {
                "dns_records": {"A": ["1.2.3.4"]},
                "subdomains": {"results": [{"domain": "sub.example.com"}]},
            }
        }
        # The get_all_scans_for_target function returns a list of dictionaries

        mock_get_scans.return_value = [
            {"module": "footprint", "scan_data": json.dumps(scan_data)}
        ]

        # Act: Build the graph

        graph_result = build_and_save_graph("example.com")

        # Assert

        self.assertIsNotNone(graph_result)
        self.assertIsNone(graph_result.error)
        self.assertEqual(graph_result.total_nodes, 3)  # target, ip, subdomain
        self.assertEqual(graph_result.total_edges, 2)
        # Verify that the function attempted to save the graph to the DB

        mock_get_conn.assert_called_once()


if __name__ == "__main__":
    unittest.main()
