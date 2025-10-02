import unittest
from unittest.mock import patch
from typer.testing import CliRunner
from chimera_intel.core.graph_analyzer import graph_app
from chimera_intel.core.graph_schemas import EntityGraphResult, GraphNarrativeResult

runner = CliRunner()


class TestGraphAnalyzer(unittest.TestCase):
    """Test cases for the Graph Analyzer module."""

    @patch("chimera_intel.core.graph_analyzer.build_and_save_graph")
    def test_build_graph_command_success(self, mock_build_and_save):
        """Tests the build-graph CLI command."""
        mock_build_and_save.return_value = EntityGraphResult(
            target="example.com", total_nodes=10, total_edges=9
        )
        result = runner.invoke(graph_app, ["build", "example.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully built graph", result.stdout)

    @patch("chimera_intel.core.graph_analyzer.generate_narrative_from_graph")
    def test_narrate_graph_command_success(self, mock_generate_narrative):
        """Tests the narrate-graph CLI command."""
        mock_generate_narrative.return_value = GraphNarrativeResult(
            narrative_text="This is a test narrative."
        )
        with patch(
            "chimera_intel.core.graph_analyzer.API_KEYS.google_api_key", "fake_key"
        ):
            result = runner.invoke(graph_app, ["narrate", "example.com"])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("test narrative", result.stdout)


if __name__ == "__main__":
    unittest.main()
