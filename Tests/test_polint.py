# Chimera-Intel/Tests/test_polint.py

import pytest
import httpx
from unittest.mock import MagicMock, AsyncMock, patch

from chimera_intel.core.ai_core import AICore
from chimera_intel.core.http_client import AsyncHTTPClient
from chimera_intel.core.graph_db import GraphDB
from chimera_intel.core.polint import PolInt

# Mock HTML responses
MOCK_FEED_HTML = """
<html>
    <body>
        <div class="feed">
            <a href="/bill/123">New Bill on Data Privacy</a>
            <a href="/bill/124">Regulations for Food Industry</a>
            <a href="/bill/125">Public Transport Act</a>
        </div>
    </body>
</html>
"""

MOCK_DOC_HTML = """
<html>
    <body>
        <div class="content">
            This bill requires all companies handling user data
            to implement new security measures.
        </div>
    </body>
</html>
"""

MOCK_AI_RESPONSE = """
Summary: A new bill focused on data privacy.
Financial_Impact: High
Operational_Impact: Medium
Key_Concerns: - New compliance requirements
Opportunity_Areas: - N/A
"""

@pytest.fixture
def mock_ai_core():
    core = MagicMock(spec=AICore)
    core.generate_response = AsyncMock(return_value=MOCK_AI_RESPONSE)
    return core

@pytest.fixture
def mock_http_client():
    client = MagicMock(spec=AsyncHTTPClient)
    
    # Mock the HTTPX Response object
    mock_feed_response = MagicMock()
    mock_feed_response.text = MOCK_FEED_HTML
    mock_feed_response.raise_for_status = MagicMock()

    mock_doc_response = MagicMock()
    mock_doc_response.text = MOCK_DOC_HTML
    mock_doc_response.raise_for_status = MagicMock()

    # Configure the get mock to return different responses based on URL
    async def mock_get(url, **kwargs):
        if "feed.gov" in url:
            return mock_feed_response
        elif "/bill/123" in url:
            return mock_doc_response
        else:
            raise httpx.HTTPStatusError("404 Not Found", request=None, response=None)
            
    client.get = AsyncMock(side_effect=mock_get)
    return client

@pytest.fixture
def mock_graph_db():
    db = MagicMock(spec=GraphDB)
    db.add_node = AsyncMock()
    db.add_edge = AsyncMock()
    return db

@pytest.fixture
def polint_service(mock_ai_core, mock_http_client, mock_graph_db):
    return PolInt(ai_core=mock_ai_core, http_client=mock_http_client, graph=mock_graph_db)

@pytest.mark.asyncio
async def test_polint_initialization(polint_service):
    assert polint_service.ai_core is not None
    assert polint_service.http_client is not None
    assert polint_service.graph is not None

@pytest.mark.asyncio
async def test_analyze_document_impact(polint_service, mock_ai_core):
    doc_text = "This is a test document about a new law."
    target_company = "TestCorp"
    target_industry = "Tech"
    
    result = await polint_service.analyze_document_impact(doc_text, target_company, target_industry)
    
    # Check that AI core was called with the correct prompt
    mock_ai_core.generate_response.assert_called_once()
    prompt_arg = mock_ai_core.generate_response.call_args[0][0]
    assert doc_text in prompt_arg
    assert target_company in prompt_arg
    assert target_industry in prompt_arg
    
    # Check that the response was parsed correctly
    assert result['summary'] == "A new bill focused on data privacy."
    assert result['financial_impact'] == "High"
    assert result['operational_impact'] == "Medium"

@pytest.mark.asyncio
async def test_store_findings(polint_service, mock_graph_db):
    analysis = {
        'summary': 'Test summary',
        'financial_impact': 'Low',
        'operational_impact': 'Low'
    }
    source_url = "http://example.com/bill"
    target_company = "TestCorp"
    document_title = "Test Bill"
    
    await polint_service.store_findings(analysis, source_url, target_company, document_title)
    
    # Check that nodes and edges are added
    assert mock_graph_db.add_node.call_count == 2
    assert mock_graph_db.add_edge.call_count == 1
    
    # Check Company Node
    company_node_call = mock_graph_db.add_node.call_args_list[0][0][0]
    assert company_node_call.id == "testcorp"
    assert company_node_call.label == "Company"
    assert company_node_call.properties['name'] == "TestCorp"

    # Check Policy Node
    policy_node_call = mock_graph_db.add_node.call_args_list[1][0][0]
    assert policy_node_call.id == "policy:test_bill"
    assert policy_node_call.label == "PolicyIssue"
    assert policy_node_call.properties['source_url'] == source_url
    assert policy_node_call.properties['summary'] == analysis['summary']

    # Check Edge
    edge_call = mock_graph_db.add_edge.call_args_list[0][0][0]
    assert edge_call.from_node == "testcorp"
    assert edge_call.to_node == "policy:test_bill"
    assert edge_call.label == "AFFECTED_BY"

@pytest.mark.asyncio
async def test_process_legislative_feed(polint_service, mock_http_client, mock_ai_core, mock_graph_db):
    base_url = "http://feed.gov"
    feed_path = "/rss"
    link_selector = "div.feed a"
    keywords = ["Data Privacy"] # This should match "New Bill on Data Privacy"
    target_company = "PrivacyCorp"
    target_industry = "Data Services"
    
    results = await polint_service.process_legislative_feed(
        base_url=base_url,
        feed_path=feed_path,
        link_selector=link_selector,
        keywords=keywords,
        target_company=target_company,
        target_industry=target_industry
    )
    
    # Check that the feed URL was fetched
    mock_http_client.get.assert_any_call("http://feed.gov/rss")
    
    # Check that the matching document was fetched
    mock_http_client.get.assert_any_call("http://feed.gov/bill/123")
    
    # Check that AI analysis was called
    mock_ai_core.generate_response.assert_called_once()
    
    # Check that findings were stored
    mock_graph_db.add_node.assert_called()
    mock_graph_db.add_edge.assert_called()
    
    # Check that results are returned
    assert len(results) == 1
    assert results[0]['title'] == "New Bill on Data Privacy"
    assert results[0]['financial_impact'] == "High"