import unittest
import networkx as nx
from chimera_intel.core.c_pint import (
    model_cyber_physical_system,
    analyze_cps_for_cascading_failures,
)
from chimera_intel.core.ot_intel import OTAsset
from chimera_intel.core.geoint import GeoLocation
from chimera_intel.core.sigint import SignalIntercept
from chimera_intel.core.vulnerability_scanner import Vulnerability


class TestCPINT(unittest.TestCase):
    """Test cases for the C-PINT module."""

    def test_model_cyber_physical_system(self):
        """Tests the creation of a CPS graph."""
        ot_assets = [
            OTAsset(
                device_id="PLC1",
                device_type="PLC",
                location="SubstationA",
                vulnerabilities=["CVE-2023-1234"],
            )
        ]
        geo_locations = [
            GeoLocation(name="SubstationA", latitude=40.7128, longitude=-74.0060)
        ]
        signal_intercepts = [
            SignalIntercept(signal_id="SIG1", frequency=100.0, modulation="FSK")
        ]
        vulnerabilities = [Vulnerability(cve="CVE-2023-1234", severity="High")]

        graph = model_cyber_physical_system(
            ot_assets, geo_locations, signal_intercepts, vulnerabilities
        )
        self.assertIsInstance(graph, nx.Graph)
        self.assertIn("PLC1", graph)
        self.assertIn("SubstationA", graph)
        self.assertTrue(graph.has_edge("PLC1", "SubstationA"))
        self.assertTrue(graph.has_edge("PLC1", "CVE-2023-1234"))

    def test_analyze_cps_for_cascading_failures(self):
        """Tests the analysis of a CPS graph for failure paths."""
        G = nx.Graph()
        G.add_edges_from([("A", "B"), ("B", "C"), ("C", "D")])
        nx.set_node_attributes(G, "TestNode", "node_type")

        result = analyze_cps_for_cascading_failures(G)
        self.assertGreater(len(result.critical_nodes), 0)
        self.assertGreater(len(result.failure_paths), 0)
        self.assertIsNone(result.error)


if __name__ == "__main__":
    unittest.main()
