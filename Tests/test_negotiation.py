import pytest
import httpx
import asyncio  # Import asyncio
from chimera_intel.core.negotiation import NegotiationEngine
from webapp.main import app


@pytest.fixture
def engine():
    """Provides a NegotiationEngine instance for testing."""
    return NegotiationEngine()


def test_recommend_tactic_with_reason(engine):
    """Tests that tactic recommendations include a reason."""
    # This test is somewhat redundant with test_recommend_tactic_no_history,
    # but we'll update it to be correct.

    history = []
    recommendation = asyncio.run(engine.recommend_tactic_async(history))
    assert "tactic" in recommendation
    assert "reason" in recommendation
    assert "Opening Move" in recommendation["tactic"]


def test_recommend_tactic_with_history(engine):
    """Tests that recommendations change based on history."""
    history = [
        {
            "sender": "them",
            "content": "This is a terrible offer.",
            "analysis": {"sentiment": "negative"},
        }
    ]
    # Corrected to call async method and check for the "De-escalate" tactic

    recommendation = asyncio.run(engine.recommend_tactic_async(history))
    assert "De-escalate" in recommendation["tactic"]
    assert "negative" in recommendation["reason"]


# Updated httpx client setup

client = httpx.Client(app=app, base_url="http://test")


def test_create_negotiation():
    """Tests the creation of a new negotiation session."""
    response = client.post(
        "/api/v1/negotiations",
        json={
            "subject": "Test Negotiation",
            "participants": [{"name": "TestCorp", "type": "company"}],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] == "Test Negotiation"
    assert "id" in data


def test_analyze_message_for_negotiation():
    """Tests analyzing and saving a message."""
    # First, create a negotiation to get a valid ID

    neg_response = client.post(
        "/api/v1/negotiations", json={"subject": "Message Test", "participants": []}
    )
    negotiation_id = neg_response.json()["id"]

    # Now, post a message to it

    msg_response = client.post(
        f"/api/v1/negotiations/{negotiation_id}/messages",
        json={
            "negotiation_id": negotiation_id,
            "sender_id": "user1",
            "content": "This is a test message.",
            "channel": "chat",
        },
    )
    assert msg_response.status_code == 200
    data = msg_response.json()
    assert data["message"] == "Message analyzed and saved"
    assert "analysis" in data


def test_full_engine_functionality(engine):
    """A comprehensive test that checks core methods of the unified engine."""

    # 1. Message Analysis - Updated to remove 'intent' check

    message = "I'm not happy with this price, it's too high."
    analysis = engine.analyze_message(message)
    assert analysis["sentiment"] == "negative"
    assert "argument_tactics" in analysis  # Check for argument_tactics instead

    # 2. BATNA Assessment - Removed, method no longer exists
    # 3. ZOPA Calculation - Removed, method no longer exists

    # 4. Context-Aware Recommendation - Updated to async and correct tactic

    history = [{"sender": "them", "content": message, "analysis": analysis}]
    recommendation = asyncio.run(engine.recommend_tactic_async(history))
    assert "De-escalate" in recommendation["tactic"]
    assert "negative" in recommendation["reason"]

    # 5. Simulation - Updated to check for 'outcome'

    scenario = {
        "our_min": 10000,
        "our_max": 16000,
        "their_min": 14000,
        "their_max": 18000,
    }
    simulation = engine.simulate_outcome(scenario)
    assert "outcome" in simulation
    assert simulation["outcome"] == "Deal is Possible"


# Removed test_zopa_no_overlap - 'calculate_zopa' method no longer exists


def test_initial_recommendation(engine):
    """Tests the initial recommendation when there is no history."""
    # Updated to call async method

    recommendation = asyncio.run(engine.recommend_tactic_async([]))
    assert "Opening Move" in recommendation["tactic"]


# Removed all other obsolete/duplicate tests:
# - test_calculate_zopa_exists
# - test_recommend_tactic_no_history
# - test_create_negotiation_endpoint (duplicate of test_create_negotiation)
# - test_analyze_message_endpoint (duplicate of test_analyze_message_for_negotiation)
# - test_assess_batna
# - test_calculate_zopa_no_overlap
# - All loose functions (setUp, test_analyze_message, etc.)


def test_recommend_tactic_with_negative_history(engine):
    """Tests that recommendations change based on negative history."""
    history = [
        {
            "sender": "them",
            "content": "This is a terrible offer.",
            "analysis": {"sentiment": "negative"},
        }
    ]
    # Updated to call async method

    recommendation = asyncio.run(engine.recommend_tactic_async(history))
    assert "De-escalate" in recommendation["tactic"]
    assert "negative" in recommendation["reason"]


def test_recommend_tactic_with_stable_history(engine):
    """Tests the recommendation for a stable, neutral negotiation."""
    history = [
        {
            "sender": "them",
            "content": "That's an interesting point.",
            "analysis": {"sentiment": "neutral"},  # Use neutral for "stable"
        }
    ]
    # Updated to call async method

    recommendation = asyncio.run(engine.recommend_tactic_async(history))
    assert "Collaborative Exploration" in recommendation["tactic"]
    assert "stable" in recommendation["reason"]


def test_analyze_message_positive(engine):
    """Tests message analysis with positive sentiment."""
    result = engine.analyze_message(
        "This is a fantastic offer, I'm very happy with it."
    )
    assert result["sentiment"] == "positive"
    assert "argument_tactics" in result


def test_analyze_message_negative(engine):
    """Tests message analysis with negative sentiment."""
    result = engine.analyze_message("I'm afraid this is a terrible proposal.")
    assert result["sentiment"] == "negative"


def test_get_reward(engine):
    """Tests the get_reward function to ensure it calculates rewards as expected."""
    # Added the required 'history' argument

    history = []
    positive_state = {"last_message_sentiment": "positive"}
    negative_state = {"last_message_sentiment": "negative"}
    neutral_state = {"last_message_sentiment": "neutral"}
    offer_state = {"last_message_content": "I offer $100"}
    accept_state = {"last_message_content": "I accept"}
    reject_state = {"last_message_content": "I reject"}

    assert engine.get_reward(positive_state, history) == 0.2
    assert engine.get_reward(negative_state, history) == -0.2
    assert engine.get_reward(neutral_state, history) == 0
    assert engine.get_reward(offer_state, history) > 0
    assert engine.get_reward(accept_state, history) > 0
    assert engine.get_reward(reject_state, history) < 0


def test_simulate_outcome(engine):
    """Tests the negotiation outcome simulation."""
    scenario_deal = {
        "our_min": 10000,
        "our_max": 15000,
        "their_min": 12000,
        "their_max": 18000,
    }
    scenario_no_deal = {
        "our_min": 10000,
        "our_max": 11000,
        "their_min": 12000,
        "their_max": 18000,
    }
    result_deal = engine.simulate_outcome(scenario_deal)
    result_no_deal = engine.simulate_outcome(scenario_no_deal)

    assert result_deal["outcome"] == "Deal is Possible"
    assert result_no_deal["outcome"] == "No Deal Likely"
