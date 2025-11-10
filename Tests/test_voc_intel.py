import pytest
import json
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from chimera_intel.cli import app  # Assuming your main CLI app is here
from chimera_intel.core.voc_intel import (
    _extract_detailed_insights_ai,
    VoCAnalysisResult,
)
from chimera_intel.core.schemas import (
    SentimentTimeSeriesResult,
    TopicClusteringResult,
)

runner = CliRunner()


@pytest.fixture
def mock_docs():
    return [
        {"timestamp": "2023-01-01T10:00:00Z", "content": "The UI is slow and buggy."},
        {"timestamp": "2023-01-02T11:00:00Z", "content": "I wish it had a dark mode."},
    ]


@pytest.fixture
def mock_gemini_client():
    with patch("chimera_intel.core.voc_intel.gemini_client") as mock_client:
        mock_response = {
            "insights": [
                {
                    "category": "Complaint",
                    "topic": "UI Speed",
                    "sentiment": "Negative",
                    "quote": "The UI is slow",
                },
                {
                    "category": "Feature Request",
                    "topic": "Dark Mode",
                    "sentiment": "Neutral",
                    "quote": "I wish it had a dark mode.",
                },
            ]
        }
        mock_client.generate_response.return_value = json.dumps(mock_response)
        yield mock_client


@patch("chimera_intel.core.voc_intel.run_sentiment_time_series")
@patch("chimera_intel.core.voc_intel.run_topic_clustering")
@patch("chimera_intel.core.voc_intel.save_scan_to_db")
def test_run_voc_analysis_cli(
    mock_save_db,
    mock_run_clustering,
    mock_run_sentiment,
    mock_gemini_client,
    tmp_path,
    mock_docs,
):
    mock_run_sentiment.return_value = SentimentTimeSeriesResult(target="test")
    mock_run_clustering.return_value = TopicClusteringResult()

    # Create dummy input file
    input_file = tmp_path / "reviews.json"
    with open(input_file, "w") as f:
        json.dump(mock_docs, f)

    output_file = tmp_path / "results.json"

    result = runner.invoke(
        app,
        [
            "compete",
            "voc",
            "run",
            "MyProduct",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    mock_gemini_client.generate_response.assert_called_once()
    mock_run_sentiment.assert_called_once()
    mock_run_clustering.assert_called_once()
    mock_save_db.assert_called_once()
    
    with open(output_file, "r") as f:
        data = json.load(f)
    assert data["target"] == "MyProduct"
    assert data["total_reviews_analyzed"] == 2
    assert len(data["extracted_insights"]) == 2
    assert data["extracted_insights"][0]["topic"] == "UI Speed"


def test_extract_detailed_insights_ai(mock_gemini_client, mock_docs):
    insights = _extract_detailed_insights_ai(mock_docs)
    
    assert len(insights) == 2
    assert insights[0].category == "Complaint"
    assert insights[1].topic == "Dark Mode"
    mock_gemini_client.generate_response.assert_called_once()