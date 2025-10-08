import unittest
import networkx as nx
from chimera_intel.core.sysint import (
    model_complex_system,
    analyze_for_emergent_properties,
    OTAsset,
    MacroIndicators,
)


class TestSYSINT(unittest.TestCase):
    """Test cases for the SYSINT module, updated for robustness."""

    def setUp(self):
        """Set up a diverse set of intelligence sources for comprehensive testing."""
        self.intel_sources = {
            "cyber": [
                OTAsset(device_id="PLC1", location="USA", vulnerabilities=[]),
                OTAsset(device_id="SCADA_Gateway", location="USA", vulnerabilities=[]),
                OTAsset(device_id="PowerGrid_DE", location="DEU", vulnerabilities=[]),
                OTAsset(
                    device_id="Substation_Bridge", location="USA", vulnerabilities=[]
                ),
            ],
            "economic": [
                MacroIndicators(country="USA", gdp=22_000_000_000_000),
                MacroIndicators(country="DEU", gdp=4_000_000_000_000),
            ],
        }

    def test_model_complex_system_with_safe_dict(self):
        """Tests that the system model is created correctly and handles potential dict conflicts."""
        graph = model_complex_system(self.intel_sources)
        self.assertIsInstance(graph, nx.MultiDiGraph)

        # Verify nodes are added with correct, non-conflicting attributes

        self.assertEqual(graph.nodes["PLC1"]["layer"], "Cyber-Physical")
        self.assertEqual(graph.nodes["PLC1"]["type"], "OT Asset")
        self.assertEqual(graph.nodes["USA"]["layer"], "Economic")
        self.assertEqual(graph.nodes["USA"]["type"], "Country Macro")

        # Verify relationships are formed

        self.assertTrue(graph.has_edge("USA", "PLC1", key="economic_dependency"))
        self.assertTrue(
            graph.has_edge("USA", "SCADA_Gateway", key="economic_dependency")
        )
        self.assertTrue(
            graph.has_edge("DEU", "PowerGrid_DE", key="economic_dependency")
        )

    def test_analyze_for_all_emergent_properties(self):
        """Tests the analysis for communities, bridge nodes, and cascading failure points."""
        graph = model_complex_system(self.intel_sources)

        # Create a structure that will produce all types of emergent properties

        graph.add_edge("PLC1", "SCADA_Gateway", key="comm")
        graph.add_edge("USA", "Substation_Bridge", key="owns")
        graph.add_edge(
            "Substation_Bridge", "PowerGrid_DE", key="connects"
        )  # This makes Substation_Bridge a bridge

        result = analyze_for_emergent_properties(graph)

        self.assertIsNone(result.error)
        self.assertGreater(len(result.emergent_properties), 0)

        property_types = {p.property_type for p in result.emergent_properties}
        self.assertIn("Influential Community", property_types)
        self.assertIn("Critical Bridge Node", property_types)
        self.assertIn("Cascading Failure Point", property_types)

    def test_analysis_with_no_emergent_properties(self):
        """Tests the case where no significant properties are found, expecting a specific message."""
        # A flat, disconnected graph is unlikely to have emergent properties

        flat_intel = {
            "cyber": [OTAsset(device_id="PLC1", location="USA", vulnerabilities=[])],
            "economic": [MacroIndicators(country="DEU", gdp=4e12)],
        }
        graph = model_complex_system(flat_intel)

        result = analyze_for_emergent_properties(graph)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.emergent_properties), 1)
        self.assertEqual(
            result.emergent_properties[0].property_type,
            "No Emergent Properties Detected",
        )

    def test_analysis_with_empty_graph(self):
        """Tests that the analysis handles an empty graph gracefully, returning a specific error."""
        empty_graph = nx.MultiDiGraph()
        result = analyze_for_emergent_properties(empty_graph)
        self.assertIsNotNone(result.error)
        self.assertEqual(len(result.emergent_properties), 0)
        self.assertIn("The graph is empty", result.error)


if __name__ == "__main__":
    unittest.main()
