import pytest
from unittest.mock import MagicMock, patch
from chimera_intel.core.dashboard_service import (
    format_sentiment_time_series,
    format_seo_keyword_ranking,
    format_traffic_kpis,
    format_content_velocity,
    format_topic_coverage,
    get_dashboard_charts,
    _parse_visits,
)
from chimera_intel.core.schemas import (
    SentimentTimeSeriesResult,
    SentimentDataPoint,
    SeoIntelResult,
    SeoKeywordAnalysis,
    SeoKeywordPosition,
    TopicClusterResult,
    SeoContentVelocity,
    SimilarWebTrafficResult,
)
from datetime import datetime


@pytest.fixture
def mock_sentiment_results():
    return [
        SentimentTimeSeriesResult(
            target="test_target",
            time_series=[
                SentimentDataPoint(
                    timestamp="2023-01-01T12:00:00Z",
                    sentiment_score=0.8,
                    emotional_tone="Joy",
                    document_hint="Great news...",
                ),
                SentimentDataPoint(
                    timestamp="2023-01-02T12:00:00Z",
                    sentiment_score=-0.5,
                    emotional_tone="Anger",
                    document_hint="Bad news...",
                ),
            ],
            ran_at=datetime.now(),
        )
    ]


@pytest.fixture
def mock_seo_results():
    return [
        SeoIntelResult(
            target_domain="target.com",
            competitors=["competitor.com"],
            keyword_analysis=[
                SeoKeywordAnalysis(
                    keyword="test keyword 1",
                    target_positions=[
                        SeoKeywordPosition(
                            rank=3,
                            url="https://target.com/page1",
                            domain="target.com",
                        )
                    ],
                ),
                SeoKeywordAnalysis(
                    keyword="test keyword 2",
                    target_positions=[],  # Not ranking
                ),
            ],
            traffic_authority=SimilarWebTrafficResult(
                global_rank=12345, estimated_visits="2.5M"
            ),
            content_velocity=SeoContentVelocity(
                total_articles=3,
                articles_per_month={"2023-01": 1, "2023-02": 2},
                average_per_month=1.5,
            ),
            topic_coverage=TopicClusterResult(
                total_documents_analyzed=5,
                clusters={
                    "Topic A": ["doc1", "doc2"],
                    "Topic B": ["doc3", "doc4", "doc5"],
                },
            ),
            ran_at=datetime.now(),
        )
    ]


def test_format_sentiment_time_series(mock_sentiment_results):
    chart_data = format_sentiment_time_series(mock_sentiment_results)
    assert "data" in chart_data
    assert "layout" in chart_data
    assert chart_data["data"][0]["type"] == "scatter"
    assert chart_data["data"][0]["x"] == [
        "2023-01-01T12:00:00Z",
        "2023-01-02T12:00:00Z",
    ]
    assert chart_data["data"][0]["y"] == [0.8, -0.5]
    assert chart_data["layout"]["title"] == "Sentiment Over Time"


def test_format_seo_keyword_ranking(mock_seo_results):
    chart_data = format_seo_keyword_ranking(mock_seo_results)
    assert "data" in chart_data
    assert "layout" in chart_data
    assert chart_data["data"][0]["type"] == "bar"
    assert chart_data["data"][0]["x"] == ["test keyword 1", "test keyword 2"]
    assert chart_data["data"][0]["y"] == [3, 0]  # 0 indicates not ranking
    assert chart_data["layout"]["yaxis"]["autorange"] == "reversed"


def test_parse_visits():
    assert _parse_visits("1.2M") == 1_200_000.0
    assert _parse_visits("300k") == 300_000.0
    assert _parse_visits("1234") == 1234.0
    assert _parse_visits(None) == 0
    assert _parse_visits("N/A") == 0


def test_format_traffic_kpis(mock_seo_results):
    chart_data = format_traffic_kpis(mock_seo_results)
    assert "data" in chart_data
    assert len(chart_data["data"]) == 2  # Two indicators
    assert chart_data["data"][0]["type"] == "indicator"
    assert chart_data["data"][0]["value"] == 12345  # Rank
    assert chart_data["data"][1]["type"] == "indicator"
    assert chart_data["data"][1]["value"] == 2_500_000.0  # Visits
    assert "grid" in chart_data["layout"]


def test_format_content_velocity(mock_seo_results):
    chart_data = format_content_velocity(mock_seo_results)
    assert "data" in chart_data
    assert chart_data["data"][0]["type"] == "bar"
    assert chart_data["data"][0]["x"] == ["2023-01", "2023-02"]
    assert chart_data["data"][0]["y"] == [1, 2]
    assert chart_data["layout"]["title"] == "Content Publishing Velocity"


def test_format_topic_coverage(mock_seo_results):
    chart_data = format_topic_coverage(mock_seo_results)
    assert "data" in chart_data
    assert chart_data["data"][0]["type"] == "pie"
    assert set(chart_data["data"][0]["labels"]) == {"Topic A", "Topic B"}
    assert set(chart_data["data"][0]["values"]) == {2, 3}
    assert chart_data["layout"]["title"] == "Content Topic Coverage"


@patch("chimera_intel.core.dashboard_service.get_db")
def test_get_dashboard_charts(
    mock_get_db, mock_sentiment_results, mock_seo_results
):
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.all.side_effect = [
        mock_sentiment_results,
        mock_seo_results,
    ]
    mock_get_db.return_value = iter([mock_db])

    charts = get_dashboard_charts("test_target")

    assert "sentiment" in charts
    assert "seo_keywords" in charts
    # Check new charts
    assert "traffic_kpis" in charts
    assert "content_velocity" in charts
    assert "topic_coverage" in charts

    # Check new chart data
    assert charts["traffic_kpis"]["data"][0]["value"] == 12345
    assert charts["content_velocity"]["data"][0]["y"] == [1, 2]
    assert set(charts["topic_coverage"]["data"][0]["values"]) == {2, 3}
    assert mock_db.close.called