import pytest
from typer.testing import CliRunner
import json
from unittest.mock import patch

from chimera_intel.core.topic_clusterer import (
    topic_clusterer_app,
    run_topic_clustering,
    TopicClusteringResult,
)

runner = CliRunner()


@pytest.fixture
def mock_gemini_client():
    with patch(
        "chimera_intel.core.topic_clusterer.gemini_client"
    ) as mock_client:
        mock_response = {
            "clusters": [
                {
                    "cluster_name": "AI Regulation",
                    "document_ids": [0, 2]
                },
                {
                    "cluster_name": "Market Performance",
                    "document_ids": [1]
                }
            ]
        }
        mock_client.generate_response.return_value = json.dumps(mock_response)
        yield mock_client


@pytest.fixture
def sample_documents():
    return [
        {"timestamp": "2024-01-01", "content": "New EU law on AI safety passes."},
        {"timestamp": "2024-01-02", "content": "Stock market hits all-time high."},
        {"timestamp": "2024-01-03", "content": "US Senate debates AI ethics."},
    ]


def test_run_topic_clustering(mock_gemini_client, sample_documents):
    """Tests the core logic function."""
    
    result = run_topic_clustering(sample_documents)

    assert isinstance(result, TopicClusteringResult)
    assert not result.error
    assert result.total_documents_analyzed == 3
    assert result.total_clusters_found == 2
    assert result.unclustered_documents == 0
    
    assert result.clusters[0].cluster_name == "AI Regulation"
    assert result.clusters[0].document_indices == [0, 2]
    assert result.clusters[0].document_count == 2
    assert "New EU law" in result.clusters[0].document_hints[0]
    
    assert result.clusters[1].cluster_name == "Market Performance"
    assert result.clusters[1].document_indices == [1]


def test_topic_clusterer_cli(mock_gemini_client, tmp_path, sample_documents):
    """Tests the CLI command."""
    input_file = tmp_path / "inputs.json"
    input_file.write_text(json.dumps(sample_documents))

    output_file = tmp_path / "results.json"

    result = runner.invoke(
        topic_clusterer_app,
        [
            "run",
            "TestProject",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert output_file.exists()
    
    with open(output_file, "r") as f:
        res_json = json.load(f)
    
    assert res_json["total_documents_analyzed"] == 3
    assert res_json["total_clusters_found"] == 2
    assert "clusters" in res_json
    assert res_json["clusters"][0]["cluster_name"] == "AI Regulation"