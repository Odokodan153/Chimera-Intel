import pytest
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock, MagicMock
from chimera_intel.cli import app 

runner = CliRunner()

@pytest.fixture
def mock_blockchair_response():
    """Mock JSON response from Blockchair API."""
    return {
        "data": {
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": {
                "address": {
                    "string": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                    "balance_usd": 123456.78,
                    "received_usd": 200000.00,
                    "spent_usd": 76543.22,
                    "transaction_count": 2
                },
                "transactions": [
                    {
                        "hash": "tx_hash_1",
                        "time": "2025-01-01 10:00:00",
                        "balance_change": 100000000 # 1 BTC (in)
                    },
                    {
                        "hash": "tx_hash_2",
                        "time": "2025-01-02 11:00:00",
                        "balance_change": -50000000 # 0.5 BTC (out)
                    }
                ]
            }
        }
    }

@pytest.mark.asyncio
@patch("chimera_intel.core.blockchain_tracer.get_async_http_client")
def test_cli_trace_and_graph(mock_get_client, mock_blockchair_response, tmp_path):
    """Test the 'trace' CLI command with graph output."""
    
    # Setup mock HTTP client
    mock_response = AsyncMock()
    mock_response.json.return_value = mock_blockchair_response
    mock_response.raise_for_status = MagicMock()
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_get_client.return_value.__aenter__.return_value = mock_client
    
    output_html = tmp_path / "trace.html"
    
    # Patch pyvis Network to avoid file system calls in test
    with patch("chimera_intel.core.blockchain_tracer.Network") as mock_network:
        mock_net_instance = mock_network.return_value
        
        result = runner.invoke(
            app, # Use main app
            [
                "crypto-trace", "trace", # Command from plugin
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "--chain", "bitcoin",
                "--output", str(output_html)
            ]
        )

    assert result.exit_code == 0
    assert "Tracing 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in result.stdout
    assert "balance_usd" in result.stdout
    assert "123456.78" in result.stdout
    assert "Transaction graph saved" in result.stdout
    
    # Check that graph generation was called
    mock_network.assert_called_with(
        height="900px", width="100%", bgcolor="#222222", font_color="white", directed=True
    )
    # Check that nodes were added
    assert mock_net_instance.add_node.call_count == 5
    # Check that edges were added
    assert mock_net_instance.add_edge.call_count == 4
    # Check that graph was saved
    mock_net_instance.save_graph.assert_called_with(str(output_html))