import pytest
from typer.testing import CliRunner
import os
import json
from unittest.mock import patch

from chimera_intel.core.grapher_3d import graph_3d_app

runner = CliRunner()

@pytest.fixture
def mock_scan_json(tmp_path):
    data = {
        "domain": "example.com",
        "footprint": {
            "subdomains": {"results": [{"domain": "sub.example.com"}]},
            "dns_records": {"A": ["1.2.3.4"]}
        },
        "web_analysis": {
            "tech_stack": {"results": [{"technology": "React"}]}
        }
    }
    file_path = tmp_path / "scan.json"
    with open(file_path, "w") as f:
        json.dump(data, f)
    return file_path

@patch("chimera_intel.core.grapher_3d.go.Figure")
def test_create_3d_graph_cli(mock_figure_class, mock_scan_json, tmp_path):
    mock_fig_instance = mock_figure_class.return_value
    
    output_html = tmp_path / "output.html"
    
    result = runner.invoke(
        graph_3d_app,
        ["create-3d", str(mock_scan_json), "--output", str(output_html)]
    )
    
    assert result.exit_code == 0
    assert "3D Graph saved" in result.stdout
    
    # Check that Plotly's Figure was called
    assert mock_figure_class.called
    
    # Check that it tried to save the file
    mock_fig_instance.write_html.assert_called_with(str(output_html))
    
    # Check the data passed to Plotly
    call_args = mock_figure_class.call_args
    data = call_args[1]['data']
    layout = call_args[1]['layout']
    
    assert len(data) == 2 # 1 trace for edges, 1 for nodes
    edge_trace, node_trace = data
    
    # 4 nodes: target, subdomain, IP, tech
    assert len(node_trace.x) == 4
    assert "example.com" in node_trace.text[0]
    
    # 3 edges: target->sub, target->ip, target->tech
    assert edge_trace.x.count(None) == 3 
    
    assert layout.scene.bgcolor == "#111111" # Check for dark theme