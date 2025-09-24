import unittest
import os
from chimera_intel.core.graph_db import build_and_save_graph, DB_FILE
from chimera_intel.core.database import initialize_database, save_scan_to_db


class TestGraphDb(unittest.TestCase):
    """Test cases for the Graph Database module."""

    def setUp(self):
        """Set up a clean database for each test."""
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        initialize_database()

    def tearDown(self):
        """Remove the database file after each test."""
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

    def test_build_and_save_graph(self):
        """Tests building and saving a graph from scan data."""
        # Add some mock scan data

        scan_data = {
            "footprint": {
                "dns_records": {"A": ["1.2.3.4"]},
                "subdomains": {"results": [{"domain": "sub.example.com"}]},
            }
        }
        save_scan_to_db("example.com", "footprint", scan_data)

        # Build the graph

        graph_result = build_and_save_graph("example.com")

        self.assertIsNotNone(graph_result)
        self.assertEqual(graph_result.total_nodes, 3)  # target, ip, subdomain
        self.assertEqual(graph_result.total_edges, 2)


if __name__ == "__main__":
    unittest.main()
