# Tests/test_market_demand_intel.py

import pytest
import pytest_asyncio
from unittest.mock import patch, MagicMock, AsyncMock, MagicMock
import pandas as pd
import asyncio
from datetime import date

from chimera_intel.core.market_demand_intel import (
    estimate_tam_sam_som,
    track_demand_trends,
    discover_categories,
    _get_google_trends,
)
from chimera_intel.core.schemas import TopicClusteringResult, TopicCluster, GNewsResult, GNewsArticle, GNewsArticleSource
from chimera_intel.core.ai_core import SWOTAnalysisResult

# Mocks for reused components
mock_google_search = MagicMock()
mock_generate_swot = MagicMock()
mock_run_clustering = MagicMock()
mock_get_news = AsyncMock()
mock_async_client_get = AsyncMock()

# Mock for new dependency (pytrends)
mock_pytrends = MagicMock()
mock_pytrends_instance = MagicMock()

@pytest.fixture(autouse=True)
def mock_dependencies():
    """Mock all external and internal dependencies."""
    with patch("chimera_intel.core.market_demand_intel.google_search", mock_google_search), \
         patch("chimera_intel.core.market_demand_intel.generate_swot_from_data", mock_generate_swot), \
         patch("chimera_intel.core.market_demand_intel.run_topic_clustering", mock_run_clustering), \
         patch("chimera_intel.core.market_demand_intel.get_news_gnews", mock_get_news), \
         patch("chimera_intel.core.market_demand_intel.async_client.get", mock_async_client_get), \
         patch("chimera_intel.core.market_demand_intel.TrendReq", mock_pytrends):
        
        # Configure mocks
        mock_google_search.return_value = ["http://example.com/report1"]
        
        mock_async_client_get.return_value = MagicMock(
            text="<p>The market size is $100B.</p>",
            raise_for_status=MagicMock()
        )
        
        mock_generate_swot.return_value = SWOTAnalysisResult(
            analysis_text="""
            - **TAM (Total Addressable Market):** $100B (Source: http://example.com/report1)
            - **SAM (Serviceable Addressable Market):** $50B
            - **SOM (Serviceable Obtainable Market):** $10B
            - **Key Data Points:**
              - $100B market size (Source: http://example.com/report1)
            - **Methodology:** Extracted from scraped data.
            """
        )
        
        mock_run_clustering.return_value = TopicClusteringResult(
            total_documents_analyzed=1,
            total_clusters_found=1,
            clusters=[
                TopicCluster(cluster_id=0, cluster_name="AI Features", document_indices=[0], document_hints=["AI..."], document_count=1)
            ]
        )
        
        mock_get_news.return_value = GNewsResult(
            totalArticles=1,
            articles=[
                GNewsArticle(
                    title="AI Demand Soars",
                    description="New AI features are in high demand.",
                    content="...",
                    url="http://news.com/ai",
                    image="http://image.com",
                    publishedAt="2024-01-01T00:00:00Z",
                    source=GNewsArticleSource(name="News", url="http://news.com")
                )
            ]
        )

        # Configure pytrends mock
        mock_pytrends.return_value = mock_pytrends_instance
        mock_pytrends_instance.interest_over_time.return_value = pd.DataFrame(
            {"date": [date(2024, 1, 1)], "TestKeyword": [80], "isPartial": [False]}
        ).set_index("date")
        
        # Mock API_KEYS
        with patch("chimera_intel.core.market_demand_intel.API_KEYS.google_api_key", "fake_google_key"), \
             patch("chimera_intel.core.market_demand_intel.API_KEYS.gnews_api_key", "fake_gnews_key"):
            
            yield

@pytest.mark.asyncio
async def test_estimate_tam_sam_som_success():
    """Test successful TAM/SAM/SOM estimation."""
    result = await estimate_tam_sam_som("AI", "Large Language Models", "USA")
    
    assert result.error is None
    assert result.tam == "$100B (Source: http://example.com/report1)"
    assert result.som == "$10B"
    assert "Extracted from scraped data" in result.methodology
    mock_google_search.assert_called_once()
    mock_async_client_get.assert_called_once()
    mock_generate_swot.assert_called_once()

@pytest.mark.asyncio
async def test_track_demand_trends_success():
    """Test successful trend tracking, including sync pytrends call."""
    
    # We must patch the sync function _get_google_trends,
    # as mocking the executor call is complex.
    with patch("chimera_intel.core.market_demand_intel._get_google_trends", MagicMock()) as mock_get_trends_sync:
        
        mock_get_trends_sync.return_value = {
            "TestKeyword": [{"date": "2024-01-01", "value": 80}]
        }
        
        results = await track_demand_trends(["TestKeyword"], geo="US")
        
        assert len(results) == 1
        trend = results[0]
        assert trend.keyword == "TestKeyword"
        assert len(trend.interest_over_time) == 1
        assert trend.interest_over_time[0].value == 80
        assert trend.emerging_topics_cluster.total_clusters_found == 1
        assert trend.emerging_topics_cluster.clusters[0].cluster_name == "AI Features"
        assert trend.ai_summary is not None
        
        mock_get_news.assert_called_once()
        mock_run_clustering.assert_called_once()
        mock_generate_swot.assert_called_once()

@pytest.mark.asyncio
async def test_discover_categories_success():
    """Test successful category discovery."""
    
    mock_google_search.return_value = ["http://example.com/features"]
    mock_async_client_get.return_value = MagicMock(
        text="<p>Our product has AI Features and Cloud Sync.</p>",
        raise_for_status=MagicMock()
    )
    
    result = await discover_categories("CRM Software")
    
    assert result.error is None
    assert result.total_clusters_found == 1
    assert result.clusters[0].cluster_name == "AI Features"
    mock_google_search.assert_called_once()
    mock_async_client_get.assert_called_once()
    mock_run_clustering.assert_called_once()