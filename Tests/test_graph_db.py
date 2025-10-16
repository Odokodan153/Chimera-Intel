import unittest
import os
from chimera_intel.core.graph_db import build_and_save_graph


class TestGraphDb(unittest.TestCase):
    """Test cases for the Graph Database module."""

    def test_build_and_save_graph(self):
        """Tests building and saving a graph from scan data."""
        # Arrange: Provide mock scan data.
        json_data = {
            "domain": "example.com",
            "footprint": {
                "dns_records": {"A": ["1.2.3.4"]},
                "subdomains": {"results": [{"domain": "sub.example.com"}]},
            }
        }
        output_path = "test_graph.html"

        # Act: Build the graph
        graph_result = build_and_save_graph(json_data, output_path)

        # Assert
        self.assertIsNotNone(graph_result)
        self.assertIsNone(graph_result.error)
        self.assertEqual(graph_result.total_nodes, 3)  # target, ip, subdomain
        self.assertEqual(graph_result.total_edges, 2)
        
        # Verify that the function created the HTML file
        self.assertTrue(os.path.exists(output_path))
        
        # Clean up the created file
        os.remove(output_path)


if __name__ == "__main__":
    unittest.main()