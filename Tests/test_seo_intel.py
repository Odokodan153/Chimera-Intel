import pytest
import json
import asyncio
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

# Assuming 'app' is the main Typer app from 'chimera_intel.cli'
from chimera_intel.cli import app 
from chimera_intel.core.seo_intel import (
    _get_domain,
    _analyze_keyword_gap,
    _analyze_backlinks,
    _analyze_content_velocity,
    SeoIntelResult
)
from chimera_intel.core.schemas import TopicClusteringResult

runner = CliRunner()


@pytest.fixture
def mock_content_file(tmp_path):
    """Fixture to create a dummy JSON content file for velocity testing."""
    docs = [
        {"timestamp": "2023-01-01T10:00:00Z", "content": "Article one"},
        {"timestamp": "2023-01-15T10:00:00Z", "content": "Article two"},
        {"timestamp": "2023-02-05T10:00:00Z", "content": "Article three"},
    ]
    input_file = tmp_path / "content.json"
    with open(input_file, "w") as f:
        json.dump(docs, f)
    return input_file


def test_get_domain():
    """Tests the domain extraction helper function."""
    assert _get_domain("https://blog.example.com/path/to/page") == "example.com"
    assert _get_domain("http://example.com") == "example.com"
    # Tests the known behavior of the simple split
    assert _get_domain("https://www.google.co.uk") == "co.uk" 
    assert _get_domain("invalid-url") == "unknown"
    assert _get_domain("http://192.168.1.1/admin") == "168.1.1"


def test_analyze_content_velocity(mock_content_file):
    """Tests the content velocity logic."""
    with open(mock_content_file, "r") as f:
        docs = json.load(f)
        
    velocity = _analyze_content_velocity(docs)
    
    assert velocity.total_articles == 3
    assert velocity.articles_per_month["2023-01"] == 2
    assert velocity.articles_per_month["2023-02"] == 1
    assert velocity.average_per_month == 1.5


@patch("chimera_intel.core.seo_intel.simple_google_search")
def test_analyze_backlinks(mock_google_search):
    """Tests the real mention-based backlink analysis."""
    mock_google_search.return_value = [
        "https://other-site.com/mention-target",
        "https://another.net/blog-post",
        "https://other-site.com/another-mention"
    ]
    
    report = _analyze_backlinks("target.com")

    # Verifies the correct query is used
    mock_google_search.assert_called_with(
        ['"target.com" -site:target.com'], num_results=50
    )
    
    assert report.total_mentions_found == 3
    assert "other-site.com" in report.top_mentioning_domains
    assert "another.net" in report.top_mentioning_domains
    assert report.top_mentioning_domains[0] == "other-site.com" # Test sorting


@patch("chimera_intel.core.seo_intel.gemini_client")
@patch("chimera_intel.core.seo_intel.simple_google_search")
def test_analyze_keyword_gap(mock_google_search, mock_gemini):
    """Tests the real SERP analysis for a keyword."""
    mock_google_search.return_value = [
        "https://target.com/page1",
        "https://competitor.com/blog",
        "https://other.com/news",
        "https://target.com/another-page"
    ]
    mock_gemini.generate_response.return_value = "AI gap summary"
    
    results = _analyze_keyword_gap(
        "target.com", ["competitor.com"], ["best widgets"]
    )
    
    # Verifies it searched for the keyword
    mock_google_search.assert_called_with(["best widgets"], num_results=10)
    # Verifies AI summary was called
    mock_gemini.generate_response.assert_called_once()
    
    assert len(results) == 1
    analysis = results[0]
    
    assert analysis.keyword == "best widgets"
    assert analysis.gap_summary == "AI gap summary"
    assert len(analysis.top_10_ranks) == 4
    
    # Check target positions
    assert len(analysis.target_positions) == 2
    assert analysis.target_positions[0].rank == 1
    assert analysis.target_positions[0].domain == "target.com"
    assert analysis.target_positions[1].rank == 4
    
    # Check competitor positions
    assert len(analysis.competitor_positions["competitor.com"]) == 1
    assert analysis.competitor_positions["competitor.com"][0].rank == 2
    assert analysis.competitor_positions["competitor.com"][0].domain == "competitor.com"


@patch("chimera_intel.core.seo_intel.save_scan_to_db")
@patch("chimera_intel.core.seo_intel.run_topic_clustering")
@patch("chimera_intel.core.seo_intel.gemini_client")
@patch("chimera_intel.core.seo_intel.simple_google_search")
@patch("chimera_intel.core.seo_intel.get_traffic_similarweb")
def test_run_seo_analysis_cli(
    mock_get_traffic,
    mock_google_search,
    mock_gemini,
    mock_run_clustering,
    mock_save_db,
    mock_content_file,
    tmp_path
):
    """Full integration test of the CLI command."""
    
    # --- Mock Setup ---
    # 1. Async traffic data
    mock_get_traffic.return_value = {"visits": 98765}
    
    # 2. Google Search (side_effect for multiple calls)
    mock_google_search.side_effect = [
        [ # Call 1: Keyword "best widgets"
            "https://target.com/product-page",
            "https://other-news.com/what-are-widgets",
            "https://competitor.com/widget-blog"
        ],
        [ # Call 2: Backlink mentions for "target.com"
            "https://cool-blog.com/links-to-target",
            "https://forum.com/posts/target-com"
        ]
    ]
    
    # 3. AI Summary
    mock_gemini.generate_response.return_value = "AI keyword summary"
    
    # 4. Topic Clustering
    mock_run_clustering.return_value = TopicClusteringResult(
        total_documents_analyzed=3, total_clusters_found=2
    )
    
    output_file = tmp_path / "seo_results.json"

    # --- Run CLI ---
    # We assume the 'seo' plugin is correctly registered with the main 'app'
    result = runner.invoke(
        app,
        [
            "seo",  # Plugin command
            "run",
            "target.com",
            "--competitor", "competitor.com",
            "--keyword", "best widgets",
            "--content-file", str(mock_content_file),
            "--output", str(output_file),
        ],
    )

    # --- Asserts ---
    assert result.exit_code == 0, result.output
    assert output_file.exists()
    
    # Check that our mocks were called correctly
    mock_get_traffic.assert_called_once()
    assert mock_google_search.call_count == 2 # 1 for keyword, 1 for backlinks
    mock_gemini.assert_called_once() # 1 for keyword summary
    mock_run_clustering.assert_called_once()
    mock_save_db.assert_called_once()

    # Check the contents of the final JSON report
    with open(output_file, "r") as f:
        data = json.load(f)
        
    assert data["target_domain"] == "target.com"
    assert data["traffic_authority"] == {"visits": 98765}
    
    # Keyword results
    assert len(data["keyword_analysis"]) == 1
    kw_data = data["keyword_analysis"][0]
    assert kw_data["keyword"] == "best widgets"
    assert kw_data["gap_summary"] == "AI keyword summary"
    assert len(kw_data["target_positions"]) == 1
    assert kw_data["target_positions"][0]["rank"] == 1
    assert len(kw_data["competitor_positions"]["competitor.com"]) == 1
    assert kw_data["competitor_positions"]["competitor.com"][0]["rank"] == 3
    
    # Backlink results
    assert data["backlink_report"]["total_mentions_found"] == 2
    assert "cool-blog.com" in data["backlink_report"]["top_mentioning_domains"]
    
    # Content results
    assert data["topic_coverage"]["total_clusters_found"] == 2
    assert data["content_velocity"]["total_articles"] == 3