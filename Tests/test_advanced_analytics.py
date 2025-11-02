import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock

# Mock the LLM client before importing the module
mock_llm_client = MagicMock()
mock_llm_client.generate_text = AsyncMock()

# Mock the get_llm_client function
mock_get_llm_client = MagicMock(return_value=mock_llm_client)

import sys
sys.modules['chimera_intel.core.llm_interface'] = MagicMock(get_llm_client=mock_get_llm_client)

# Now import the module
from chimera_intel.core.advanced_analytics import (
    PredictiveScenarioEngine,
    NarrativeInfluenceTracker,
    CorporateRiskScorer
)

@pytest.fixture(autouse=True)
def reset_mocks():
    mock_llm_client.generate_text.reset_mock()
    mock_get_llm_client.reset_mock()

@pytest.mark.asyncio
async def test_predictive_scenario_engine():
    # Setup mock response
    mock_response = """
    Step 1:
    - Narrative: Tariffs cause initial shock.
    - Variables: {'company_stock': 95, 'public_sentiment': 0.4}
    Final Summary:
    - Outcome: Negative short-term impact.
    - FinalState: {'company_stock': 90, 'public_sentiment': 0.3}
    """
    mock_llm_client.generate_text.return_value = mock_response

    engine = PredictiveScenarioEngine(llm_client=mock_llm_client)
    event_desc = "Trade tariff"
    variables = {"company_stock": 100, "public_sentiment": 0.5}
    result = await engine.simulate_event(event_desc, variables, steps=2)

    assert result['event'] == event_desc
    assert result['initial_variables'] == variables
    assert "llm_full_response" in result
    assert result['llm_full_response'] == mock_response
    mock_llm_client.generate_text.assert_called_once()
    assert "Act as a Predictive Scenario Engine" in mock_llm_client.generate_text.call_args[0][0]

@pytest.mark.asyncio
async def test_narrative_influence_tracker():
    # Setup mock response
    mock_response = "Report: Found two main narratives, one positive, one negative."
    mock_llm_client.generate_text.return_value = mock_response

    tracker = NarrativeInfluenceTracker(llm_client=mock_llm_client)
    topic = "Test Topic"
    data = ["Post 1: I love this", "Post 2: I hate this"]
    result = await tracker.track_narrative(topic, data)

    assert result['topic'] == topic
    assert result['report_summary'] == mock_response
    assert "detected_narratives" in result
    mock_llm_client.generate_text.assert_called_once()
    assert "Act as a Narrative and Influence Analyst" in mock_llm_client.generate_text.call_args[0][0]
    assert "Post 1: I love this\n---\nPost 2: I hate this" in mock_llm_client.generate_text.call_args[0][0]

@pytest.mark.asyncio
async def test_corporate_risk_scorer():
    # Setup mock response
    mock_response = """
    Geopolitical Risk Score: 50
    Market Risk Score: 60
    Reputational Risk Score: 80
    Overall Composite Risk Score: 65
    Executive Summary: Risk is moderate, with a high reputational component.
    """
    mock_llm_client.generate_text.return_value = mock_response

    scorer = CorporateRiskScorer(llm_client=mock_llm_client)
    company = "TestCorp"
    signals = {"pr": "Bad press", "financial": "Good profits"}
    result = await scorer.calculate_risk_score(company, signals)

    assert result['company_name'] == company
    assert "overall_risk_score" in result
    assert "executive_summary" in result
    assert result['llm_response'] == mock_response
    mock_llm_client.generate_text.assert_called_once()
    assert "Act as a Corporate Risk Analyst" in mock_llm_client.generate_text.call_args[0][0]
    assert "PR: Bad press" in mock_llm_client.generate_text.call_args[0][0]
    assert "Financial: Good profits" in mock_llm_client.generate_text.call_args[0][0]

@pytest.mark.asyncio
async def test_init_with_default_client():
    # Test that get_llm_client is called if no client is provided
    mock_get_llm_client.return_value = mock_llm_client
    
    engine = PredictiveScenarioEngine()
    assert engine.llm_client == mock_llm_client
    mock_get_llm_client.assert_called()

    tracker = NarrativeInfluenceTracker()
    assert tracker.llm_client == mock_llm_client
    
    scorer = CorporateRiskScorer()
    assert scorer.llm_client == mock_llm_client