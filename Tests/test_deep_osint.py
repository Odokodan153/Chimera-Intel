# Tests/test_deep_osint.py

import pytest
import unittest.mock as mock
import networkx as nx
from chimera_intel.core.deep_osint import DarkSocialMonitor, IoTDeviceScanner, DeepGraphAnalyzer
from chimera_intel.core.graph_db import GraphDB # Import base class for mocking

# --- Mocks ---

@pytest.fixture
def mock_graph_db():
    """Mocks the GraphDB and its get_nx_graph method."""
    mock_db = mock.Mock(spec=GraphDB)
    
    # Create a simple graph for testing
    G = nx.Graph()
    G.add_edges_from([
        ("Company_A", "Contractor_B"),
        ("Contractor_B", "Subsidiary_C"),
        ("Company_A", "Partner_D"),
        ("Subsidiary_C", "Person_E"),
        ("Partner_D", "Person_E")
    ])
    
    # Add mock relationship types (adjust to your schema)
    nx.set_edge_attributes(G, {
        ("Company_A", "Contractor_B"): {"relation": "CONTRACTOR_FOR"},
        ("Contractor_B", "Subsidiary_C"): {"relation": "PARENT_OF"},
        ("Company_A", "Partner_D"): {"relation": "PARTNER_OF"},
        ("Subsidiary_C", "Person_E"): {"relation": "EMPLOYEE_OF"},
        ("Partner_D", "Person_E"): {"relation": "ASSOCIATE_OF"},
    })
    
    mock_db.get_nx_graph.return_value = G
    return mock_db

@pytest.fixture
def dark_social_monitor():
    """Fixture for DarkSocialMonitor."""
    return DarkSocialMonitor()

@pytest.fixture
def iot_scanner():
    """Fixture for IoTDeviceScanner."""
    return IoTDeviceScanner(shodan_api_key="MOCK_KEY")

@pytest.fixture
def graph_analyzer(mock_graph_db):
    """Fixture for DeepGraphAnalyzer, injected with the mock DB."""
    return DeepGraphAnalyzer(graph_db=mock_graph_db)

# --- Tests ---

def test_dark_social_monitor_run(dark_social_monitor):
    keywords = ["exploit", "internal"]
    data = {"keywords": keywords}
    
    # Mock the internal clients
    with mock.patch("chimera_intel.core.deep_osint.DarkSocialAPIClient.search_groups") as mock_search:
        mock_search.return_value = [{"platform": "mock", "message": "found exploit"}]
        
        result = dark_social_monitor.run(data)
        
        assert result["status"] == "success"
        assert "telegram" in result["data"]
        assert "discord" in result["data"]
        assert result["data"]["telegram"][0]["message"] == "found exploit"

def test_iot_scanner_run(iot_scanner):
    query = 'port:8080'
    data = {"query": query}
    
    # Mock the internal client
    with mock.patch("chimera_intel.core.deep_osint.ShodanClient.search_devices") as mock_search:
        mock_search.return_value = [{"ip_str": "192.0.2.1", "port": 8080}]
        
        result = iot_scanner.run(data)
        
        assert result["status"] == "success"
        assert result["data"]["count"] == 1
        assert result["data"]["devices"][0]["ip_str"] == "192.0.2.1"

def test_deep_graph_find_indirect_paths(graph_analyzer):
    data = {
        "task": "find_indirect_paths",
        "start_node": "Company_A",
        "end_node": "Person_E",
        "max_depth": 4
    }
    
    result = graph_analyzer.run(data)
    
    assert result["status"] == "success"
    assert len(result["paths"]) == 2
    # Check that it found the two indirect paths
    assert ["Company_A", "Contractor_B", "Subsidiary_C", "Person_E"] in result["paths"]
    assert ["Company_A", "Partner_D", "Person_E"] in result["paths"]

def test_deep_graph_find_indirect_paths_no_direct(graph_analyzer):
    # This test ensures direct paths are filtered out
    data = {
        "task": "find_indirect_paths",
        "start_node": "Company_A",
        "end_node": "Partner_D", # This is a direct path
        "max_depth": 2
    }
    
    result = graph_analyzer.run(data)
    assert result["status"] == "success"
    assert len(result["paths"]) == 0 # No indirect paths

def test_deep_graph_find_partners(graph_analyzer):
    data = {
        "task": "find_partners",
        "company_node": "Company_A",
        "relationship_type": "PARTNER_OF",
        "depth": 1
    }
    
    result = graph_analyzer.run(data)
    
    assert result["status"] == "success"
    assert "Partner_D" in result["entities"]
    assert "Contractor_B" not in result["entities"] # Wrong relationship type