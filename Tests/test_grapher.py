import unittest
from unittest.mock import patch
from chimera_intel.core.grapher import generate_knowledge_graph


class TestGrapher(unittest.TestCase):
    """Test cases for the grapher module."""

    @patch("chimera_intel.core.grapher.Network")
    def test_generate_knowledge_graph_success(self, mock_network):
        """Tests a successful knowledge graph generation."""
        mock_net_instance = mock_network.return_value

        test_data = {
            "domain": "example.com",
            "footprint": {
                "subdomains": {"results": [{"domain": "sub.example.com"}]},
                "dns_records": {"A": ["1.1.1.1"]},
            },
            "web_analysis": {"tech_stack": {"results": [{"technology": "React"}]}},
        }

        generate_knowledge_graph(test_data, "test_graph.html")

        # Verify that nodes were added for all data points

        self.assertGreaterEqual(
            mock_net_instance.add_node.call_count, 4
        )  # target, sub, ip, tech
        # Verify that edges were added to connect them

        self.assertGreaterEqual(mock_net_instance.add_edge.call_count, 3)
        # Verify that the graph was saved

        mock_net_instance.save_graph.assert_called_with("test_graph.html")

    @patch("chimera_intel.core.grapher.Network")
    def test_generate_knowledge_graph_empty_data(self, mock_network):
        """Tests graph generation with minimal/empty data."""
        mock_net_instance = mock_network.return_value

        test_data = {"domain": "example.com"}  # No footprint or web analysis

        generate_knowledge_graph(test_data, "test_graph.html")

        # Should still add the main target node

        mock_net_instance.add_node.assert_called_once_with(
            "example.com",
            label="example.com",
            color="#ff4757",
            size=30,
            shape="dot",
            title="Main Target",
        )
        mock_net_instance.save_graph.assert_called_once()

    @patch("chimera_intel.core.grapher.Network")
    def test_generate_knowledge_graph_exception(self, mock_network):
        """Tests graph generation when an unexpected error occurs."""
        mock_net_instance = mock_network.return_value
        mock_net_instance.save_graph.side_effect = Exception("Failed to save graph")

        with patch("logging.Logger.error") as mock_logger_error:
            generate_knowledge_graph({}, "test.html")
            mock_logger_error.assert_called_once()
            self.assertIn(
                "An error occurred during graph generation",
                mock_logger_error.call_args[0][0],
            )


if __name__ == "__main__":
    unittest.main()
