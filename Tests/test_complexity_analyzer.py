import unittest
from unittest.mock import patch, MagicMock
import networkx as nx
from typer.testing import CliRunner

from chimera_intel.core.complexity_analyzer import (
    build_system_graph,
    analyze_systemic_risk,
    complexity_analyzer_app,
)
from chimera_intel.core.schemas import ComplexityAnalysisResult

runner = CliRunner()


class TestComplexityAnalyzer(unittest.TestCase):

    @patch("chimera_intel.core.complexity_analyzer.get_aggregated_data_for_target")
    def test_build_system_graph(self, mock_get_data):
        """Tests the construction of the system graph from aggregated data."""
        # Arrange
        target = "example.com"
        mock_get_data.return_value = {
            "modules": {
                "personnel_osint_emails": {
                    "employee_profiles": [{"email": "ceo@example.com"}]
                },
                "footprint_subdomains": {
                    "subdomains": ["app.example.com"]
                },
                "corporate_supplychain": {
                    "shipments": [{"shipper": "SupplierA"}]
                },
            }
        }

        # Act
        graph = build_system_graph(target)

        # Assert
        self.assertIsInstance(graph, nx.Graph)
        self.assertIn("example.com", graph)
        self.assertIn("ceo@example.com", graph)
        self.assertIn("app.example.com", graph)
        self.assertIn("SupplierA", graph)
        self.assertTrue(graph.has_edge("example.com", "ceo@example.com"))
        self.assertTrue(graph.has_edge("example.com", "app.example.com"))
        self.assertTrue(graph.has_edge("example.com", "SupplierA"))
        self.assertEqual(graph.nodes["example.com"]["type"], "target_company")
        self.assertEqual(graph.nodes["ceo@example.com"]["type"], "personnel")
        self.assertEqual(graph.nodes["app.example.com"]["type"], "domain")
        self.assertEqual(graph.nodes["SupplierA"]["type"], "supplier")

    def test_analyze_systemic_risk(self):
        """Tests the risk analysis on a sample graph."""
        # Arrange
        target = "A"
        G = nx.Graph()
        G.add_edges_from([("A", "B"), ("B", "C"), ("A", "D"), ("D", "E")])
        # In this graph, B and D are articulation points.
        # A is the most central node by degree.

        # Act
        result = analyze_systemic_risk(target, G)

        # Assert
        self.assertIsInstance(result, ComplexityAnalysisResult)
        self.assertIsNone(result.error)
        self.assertEqual(result.node_count, 5)
        self.assertEqual(result.edge_count, 4)
        
        # Check High-Centrality
        self.assertEqual(result.systemic_risks[0].risk_type, "High-Centrality Node")
        self.assertIn("A", result.systemic_risks[0].affected_nodes)
        
        # Check Articulation Points
        self.assertEqual(result.systemic_risks[1].risk_type, "Cascading Failure Point")
        self.assertIn("B", result.systemic_risks[1].affected_nodes)
        self.assertIn("D", result.systemic_risks[1].affected_nodes)

    def test_analyze_systemic_risk_no_graph(self):
        """Tests risk analysis with an empty graph."""
        # Arrange
        target = "A"
        G = nx.Graph()

        # Act
        result = analyze_systemic_risk(target, G)

        # Assert
        self.assertIsInstance(result, ComplexityAnalysisResult)
        self.assertIsNotNone(result.error)
        self.assertIn("No system graph could be built", result.error)

    @patch("chimera_intel.core.complexity_analyzer.resolve_target")
    @patch("chimera_intel.core.complexity_analyzer.build_system_graph")
    @patch("chimera_intel.core.complexity_analyzer.analyze_systemic_risk")
    @patch("chimera_intel.core.complexity_analyzer.save_or_print_results")
    @patch("chimera_intel.core.complexity_analyzer.save_scan_to_db")
    def test_cli_complexity_analysis_run(
        self, mock_save_db, mock_save_print, mock_analyze, mock_build, mock_resolve
    ):
        """Tests the 'run' CLI command for complexity-analysis."""
        # Arrange
        mock_resolve.return_value = "example.com"
        mock_graph = nx.Graph()
        mock_build.return_value = mock_graph
        
        mock_dump_dict = {"target": "example.com", "node_count": 0}
        mock_result = MagicMock(model_dump=lambda exclude_none: mock_dump_dict)
        mock_analyze.return_value = mock_result

        # Act
        result = runner.invoke(complexity_analyzer_app, ["run", "example.com"])

        # Assert
        self.assertEqual(result.exit_code, 0)
        mock_resolve.assert_called_with("example.com")
        mock_build.assert_called_with("example.com")
        mock_analyze.assert_called_with("example.com", mock_graph)
        mock_save_print.assert_called_with(mock_dump_dict, None)
        mock_save_db.assert_called_with(
            target="example.com", module="complexity_analysis", data=mock_dump_dict
        )