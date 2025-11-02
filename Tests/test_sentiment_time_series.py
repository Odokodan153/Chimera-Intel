import pytest
from typer.testing import CliRunner
import json
from unittest.mock import patch, call

from chimera_intel.core.sentiment_time_series import (
    sentiment_time_series_app,
    run_sentiment_time_series,
    detect_sentiment_anomalies,
)
from chimera_intel.core.schemas import SentimentTimeSeriesResult, SentimentDataPoint

runner = CliRunner()


@pytest.fixture
def mock_gemini_client():
    with patch(
        "chimera_intel.core.sentiment_time_series.gemini_client"
    ) as mock_client:
        # Define a series of responses
        mock_responses = [
            json.dumps({"sentiment_score": 0.1, "emotional_tone": "Neutral"}),
            json.dumps({"sentiment_score": 0.2, "emotional_tone": "Optimistic"}),
            json.dumps({"sentiment_score": 0.1, "emotional_tone": "Neutral"}),
            json.dumps({"sentiment_score": 0.3, "emotional_tone": "Optimistic"}),
            json.dumps({"sentiment_score": -0.8, "emotional_tone": "Anger"}), # Anomaly
            json.dumps({"sentiment_score": 0.2, "emotional_tone": "Neutral"}),
        ]
        mock_client.generate_response.side_effect = mock_responses
        yield mock_client


def test_detect_sentiment_anomalies():
    """Tests the anomaly detection logic separately."""
    time_series = [
        SentimentDataPoint(timestamp="2024-01-01T00:00:00", sentiment_score=0.1, emotional_tone="Neutral", document_hint="..."),
        SentimentDataPoint(timestamp="2024-01-02T00:00:00", sentiment_score=0.2, emotional_tone="Neutral", document_hint="..."),
        SentimentDataPoint(timestamp="2024-01-03T00:00:00", sentiment_score=0.1, emotional_tone="Neutral", document_hint="..."),
        SentimentDataPoint(timestamp="2024-01-04T00:00:00", sentiment_score=0.2, emotional_tone="Neutral", document_hint="..."),
        SentimentDataPoint(timestamp="2024-01-05T00:00:00", sentiment_score=-0.9, emotional_tone="Anger", document_hint="Bad news..."),
        SentimentDataPoint(timestamp="2024-01-06T00:00:00", sentiment_score=0.1, emotional_tone="Neutral", document_hint="..."),
    ]
    
    anomalies = detect_sentiment_anomalies(time_series)
    assert len(anomalies) == 1
    assert anomalies[0].shift_direction == "Negative"
    assert "Bad news..." in anomalies[0].document_hint
    assert anomalies[0].timestamp == "2024-01-05T00:00:00"


def test_run_sentiment_time_series(mock_gemini_client):
    """Tests the core logic function."""
    documents = [
        {"timestamp": "2024-01-01T00:00:00", "content": "Stock is stable."},
        {"timestamp": "2024-01-02T00:00:00", "content": "Stock is up."},
        {"timestamp": "2024-01-03T00:00:00", "content": "Stock is stable again."},
        {"timestamp": "2024-01-04T00:00:00", "content": "Stock is up again."},
        {"timestamp": "2024-01-05T00:00:00", "content": "Massive crash! Terrible news!"},
        {"timestamp": "2024-01-06T00:00:00", "content": "Things are ok."},
    ]
    
    result = run_sentiment_time_series("Stock", documents)

    assert isinstance(result, SentimentTimeSeriesResult)
    assert not result.error
    assert result.total_documents_analyzed == 6
    assert len(result.time_series) == 6
    assert result.time_series[4].sentiment_score == -0.8
    assert result.time_series[4].emotional_tone == "Anger"
    
    # Check if anomaly detection was triggered and found the dip
    assert len(result.anomalies) == 1
    assert result.anomalies[0].shift_direction == "Negative"
    assert "Massive crash!" in result.anomalies[0].document_hint


def test_sentiment_time_series_cli(mock_gemini_client, tmp_path):
    """Tests the CLI command."""
    documents = [
        {"timestamp": "2024-01-01T00:00:00", "content": "Doc 1"},
        {"timestamp": "2024-01-02T00:00:00", "content": "Doc 2"},
        {"timestamp": "2024-01-03T00:00:00", "content": "Doc 3"},
        {"timestamp": "2024-01-04T00:00:00", "content": "Doc 4"},
        {"timestamp": "2024-01-05T00:00:00", "content": "Doc 5"},
        {"timestamp": "2024-01-06T00:00:00", "content": "Doc 6"},
    ]
    input_file = tmp_path / "inputs.json"
    input_file.write_text(json.dumps(documents))

    output_file = tmp_path / "results.json"

    result = runner.invoke(
        sentiment_time_series_app,
        [
            "run",
            "TestTopic",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    
    with open(output_file, "r") as f:
        res_json = json.load(f)
    
    assert res_json["target"] == "TestTopic"
    assert "time_series" in res_json
    assert len(res_json["time_series"]) == 6
    assert "anomalies" in res_json
    assert len(res_json["anomalies"]) == 1