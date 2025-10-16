import unittest
from unittest.mock import patch, mock_open
from typer.testing import CliRunner

from chimera_intel.core.grapher import generate_knowledge_graph, graph_app

runner = CliRunner()


class TestGrapher(unittest.TestCase):
    """Test cases for the knowledge graph generator module."""

    # --- Function Tests ---

    @patch("chimera_intel.core.grapher.Network")
    def test_generate_knowledge_graph_success(self, mock_network):
        """Tests the successful generation of a knowledge graph."""
        # Arrange

        mock_net_instance = mock_network.return_value
        json_data = {
            "domain": "example.com",
            "footprint": {
                "subdomains": {"results": [{"domain": "sub.example.com"}]},
                "dns_records": {"A": ["1.1.1.1"]},
            },
            "web_analysis": {"tech_stack": {"results": [{"technology": "nginx"}]}},
        }
        output_path = "test_graph.html"

        # Act

        generate_knowledge_graph(json_data, output_path)

        # Assert
        # Verify that nodes were added for the target, subdomain, IP, and tech

        self.assertEqual(mock_net_instance.add_node.call_count, 4)
        mock_net_instance.add_node.assert_any_call(
            "example.com",
            label="example.com",
            color="#ff4757",
            size=30,
            shape="dot",
            title="Main Target",
        )
        mock_net_instance.add_node.assert_any_call(
            "sub.example.com",
            label="sub.example.com",
            color="#1e90ff",
            size=15,
            shape="dot",
            title="Subdomain",
        )

        # Verify that edges were added to connect the nodes

        self.assertEqual(mock_net_instance.add_edge.call_count, 3)
        mock_net_instance.add_edge.assert_any_call("example.com", "sub.example.com")

        # Verify the graph was saved

        mock_net_instance.save_graph.assert_called_once_with(output_path)

    # --- CLI Tests ---

    @patch("chimera_intel.core.grapher.generate_knowledge_graph")
    def test_cli_create_knowledge_graph_success(self, mock_generate):
        """Tests the 'graph create' CLI command with a successful run."""
        # Arrange

        json_content = '{"domain": "cli-test.com"}'

        with patch("builtins.open", mock_open(read_data=json_content)):
            # Act

            result = runner.invoke(
                graph_app, ["create", "test.json", "--output", "output.html"]
            )
        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_generate.assert_called_once()
        # Check that the function was called with the parsed data and the correct output path

        self.assertEqual(mock_generate.call_args[0][0], {"domain": "cli-test.com"})
        self.assertEqual(mock_generate.call_args[0][1], "output.html")

    @patch("chimera_intel.core.grapher.generate_knowledge_graph")
    def test_cli_create_graph_default_output_path(self, mock_generate):
        """Tests that a default output path is generated if none is provided."""
        # Arrange

        json_content = '{"domain": "default.com"}'

        with patch("builtins.open", mock_open(read_data=json_content)):
            # Act

            result = runner.invoke(graph_app, ["create", "test.json"])
        # Assert

        self.assertEqual(result.exit_code, 0)
        mock_generate.assert_called_once()
        # Verify the default output path is based on the domain name

        self.assertEqual(mock_generate.call_args[0][1], "default_com_graph.html")

    def test_cli_create_graph_file_not_found(self):
        """Tests the CLI command when the input JSON file does not exist."""
        # Act

        result = runner.invoke(graph_app, ["create", "nonexistent.json"])

        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("File not found", result.stdout)

    def test_cli_create_graph_invalid_json(self):
        """Tests the CLI command when the input file contains invalid JSON."""
        # Arrange

        invalid_json_content = '{"domain": "test.com",}'  # trailing comma

        with patch("builtins.open", mock_open(read_data=invalid_json_content)):
            # Act

            result = runner.invoke(graph_app, ["create", "test.json"])
        # Assert

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid JSON", result.stdout)


if __name__ == "__main__":
    unittest.main()
