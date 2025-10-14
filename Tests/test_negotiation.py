import pytest
from chimera_intel.core.negotiation import NegotiationEngine
from fastapi.testclient import TestClient

@pytest.fixture
def engine():
    """Provides a NegotiationEngine instance for testing."""
    return NegotiationEngine()

def test_recommend_tactic_with_reason(engine):
    """Tests that tactic recommendations include a reason."""
    context = {"our_last_offer": 10000, "their_last_offer": 20000}
    recommendation = engine.recommend_tactic(context)
    assert "tactic" in recommendation
    assert "reason" in recommendation
    assert "Anchoring" in recommendation["tactic"]

def test_recommend_tactic_with_history(engine):
    """Tests that recommendations change based on history."""
    history = [
        {
            "sender_id": "them",
            "content": "This is a terrible offer.",
            "analysis": {"tone_score": -0.8},
        }
    ]
    recommendation = engine.recommend_tactic(history)
    assert "Concession" in recommendation["tactic"]
    assert "negative" in recommendation["reason"]

client = TestClient()

def test_create_negotiation():
    """Tests the creation of a new negotiation session."""
    response = client.post(
        "/api/v1/negotiations",
        json={"subject": "Test Negotiation", "participants": [{"name": "TestCorp", "type": "company"}]}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] == "Test Negotiation"
    assert "id" in data

def test_analyze_message_for_negotiation():
    """Tests analyzing and saving a message."""
    # First, create a negotiation to get a valid ID
    neg_response = client.post(
        "/api/v1/negotiations",
        json={"subject": "Message Test", "participants": []}
    )
    negotiation_id = neg_response.json()["id"]

    # Now, post a message to it
    msg_response = client.post(
        f"/api/v1/negotiations/{negotiation_id}/messages",
        json={"negotiation_id": negotiation_id, "sender_id": "user1", "content": "This is a test message.", "channel": "chat"}
    )
    assert msg_response.status_code == 200
    data = msg_response.json()
    assert data["message"] == "Message analyzed and saved"
    assert "analysis" in data

def test_full_engine_functionality(engine):
    """A comprehensive test that checks all core methods of the unified engine."""
    
    # 1. Message Analysis
    message = "I'm not happy with this price, it's too high."
    analysis = engine.analyze_message(message)
    assert analysis["sentiment"] == "negative"
    assert analysis["intent"] == "rejection"

    # 2. BATNA Assessment
    alternatives = [{"name": "Supplier A", "value": 12000}, {"name": "Supplier B", "value": 15000}]
    batna_result = engine.assess_batna(alternatives)
    assert batna_result["best_alternative"]["name"] == "Supplier B"

    # 3. ZOPA Calculation
    zopa = engine.calculate_zopa(our_min=10000, our_max=16000, their_min=14000, their_max=18000)
    assert zopa == (14000, 16000)
    
    # 4. Context-Aware Recommendation
    history = [
        {"sender_id": "them", "content": message, "analysis": analysis}
    ]
    recommendation = engine.recommend_tactic(history)
    assert "Concession" in recommendation["tactic"]
    assert "negative" in recommendation["reason"]
    
    # 5. Simulation
    scenario = {"our_min": 10000, "our_max": 16000, "their_min": 14000, "their_max": 18000}
    simulation = engine.simulate_outcome(scenario)
    assert "success_probability" in simulation
    assert 0 <= simulation["success_probability"] <= 1

def test_zopa_no_overlap(engine):
    """Tests ZOPA calculation when no agreement zone exists."""
    zopa = engine.calculate_zopa(our_min=100, our_max=140, their_min=150, their_max=250)
    assert zopa is None

def test_initial_recommendation(engine):
    """Tests the initial recommendation when there is no history."""
    recommendation = engine.recommend_tactic([])
    assert "Opening Move" in recommendation["tactic"]

def setUp(self):
        """Set up a new NegotiationEngine for each test."""
        # We test with the placeholder model for simplicity
        self.engine = NegotiationEngine()

def test_analyze_message(self):
        """Test the message analysis functionality."""
        message = "I can offer $5,000 for the lot."
        analysis = self.engine.analyze_message(message)
        self.assertIn("tone_score", analysis)
        self.assertIn("sentiment", analysis)
        self.assertEqual(analysis["intent"], "offer")
        self.assertEqual(analysis["sentiment"], "neutral")

def test_recommend_tactic_opening_move(self):
        """Test the opening move recommendation."""
        recommendation = self.engine.recommend_tactic([])
        self.assertEqual(recommendation["tactic"], "Opening Move")

def test_recommend_tactic_strategic_concession(self):
        """Test the strategic concession recommendation."""
        history = [{"analysis": {"tone_score": -0.8}}]
        recommendation = self.engine.recommend_tactic(history)
        self.assertEqual(recommendation["tactic"], "Strategic Concession")

def test_recommend_tactic_collaborative_exploration(self):
        """Test the collaborative exploration recommendation."""
        history = [{"analysis": {"tone_score": 0.2}}]
        recommendation = self.engine.recommend_tactic(history)
        self.assertEqual(recommendation["tactic"], "Collaborative Exploration")

def test_calculate_zopa(self):
        """Test the ZOPA calculation."""
        zopa = self.engine.calculate_zopa(
            our_min=5000, our_max=10000, their_min=7000, their_max=12000
        )
        self.assertEqual(zopa, (7000, 10000))

        no_zopa = self.engine.calculate_zopa(
            our_min=5000, our_max=6000, their_min=7000, their_max=8000
        )
        self.assertIsNone(no_zopa)

def test_calculate_zopa_exists(engine):
    """Tests ZOPA calculation when an agreement zone exists."""
    zopa = engine.calculate_zopa(our_min=100, our_max=200, their_min=150, their_max=250)
    assert zopa == (150, 200)

def test_recommend_tactic_no_history(engine):
    """Tests the initial recommendation when there is no history."""
    recommendation = engine.recommend_tactic([])
    assert "Opening" in recommendation["tactic"]

def test_create_negotiation_endpoint():
    """Tests the creation of a new negotiation session via the API."""
    response = client.post(
        "/api/v1/negotiations",
        json={"subject": "API Test Negotiation"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["subject"] == "API Test Negotiation"
    assert "id" in data

def test_analyze_message_endpoint():
    """Tests analyzing and saving a message via the API."""
    neg_response = client.post(
        "/api/v1/negotiations",
        json={"subject": "API Message Test"}
    )
    negotiation_id = neg_response.json()["id"]

    msg_response = client.post(
        f"/api/v1/negotiations/{negotiation_id}/messages",
        json={"sender_id": "api_user", "content": "This is another test message."}
    )
    assert msg_response.status_code == 201
    data = msg_response.json()
    assert "analysis" in data
    assert "recommended_tactic" in data

def test_assess_batna(engine):
    """Tests the BATNA assessment functionality."""
    alternatives = [
        {"name": "Option A", "value": 10000},
        {"name": "Option B", "value": 15000},
        {"name": "Option C", "value": 12000},
    ]
    result = engine.assess_batna(alternatives)
    assert result["best_alternative"]["name"] == "Option B"
    assert result["best_alternative"]["value"] == 15000

def test_calculate_zopa_no_overlap(engine):
    """Tests ZOPA calculation when no agreement zone exists."""
    zopa = engine.calculate_zopa(
        our_min=100, our_max=140, their_min=150, their_max=250
    )
    assert zopa is None

def test_recommend_tactic_with_negative_history(engine):
    """Tests that recommendations change based on negative history."""
    history = [
        {
            "sender_id": "them",
            "content": "This is a terrible offer.",
            "analysis": {"tone_score": -0.8},
        }
    ]
    recommendation = engine.recommend_tactic(history)
    assert "De-escalate" in recommendation["tactic"]
    assert "negative" in recommendation["reason"]


def test_recommend_tactic_with_stable_history(engine):
    """Tests the recommendation for a stable, neutral negotiation."""
    history = [
        {
            "sender_id": "them",
            "content": "That's an interesting point.",
            "analysis": {"tone_score": 0.2},
        }
    ]
    recommendation = engine.recommend_tactic(history)
    assert "Collaborative Exploration" in recommendation["tactic"]
    assert "stable" in recommendation["reason"]

def test_analyze_message_positive(engine):
    """Tests message analysis with positive sentiment."""
    result = engine.analyze_message("This is a fantastic offer, I'm very happy with it.")
    assert result["sentiment"] == "positive"
    assert "argument_tactics" in result

def test_analyze_message_negative(engine):
    """Tests message analysis with negative sentiment."""
    result = engine.analyze_message("I'm afraid this is a terrible proposal.")
    assert result["sentiment"] == "negative"

def test_get_reward(engine):
    """Tests the get_reward function to ensure it calculates rewards as expected."""
    positive_state = {"last_message_sentiment": "positive"}
    negative_state = {"last_message_sentiment": "negative"}
    neutral_state = {"last_message_sentiment": "neutral"}
    offer_state = {"last_message_content": "I offer $100"}
    accept_state = {"last_message_content": "I accept"}
    reject_state = {"last_message_content": "I reject"}

    assert engine.get_reward(positive_state) == 0.2
    assert engine.get_reward(negative_state) == -0.2
    assert engine.get_reward(neutral_state) == 0
    assert engine.get_reward(offer_state) > 0
    assert engine.get_reward(accept_state) > 0
    assert engine.get_reward(reject_state) < 0

def test_simulate_outcome(engine):
    """Tests the negotiation outcome simulation."""
    scenario_deal = {
        "our_min": 10000, "our_max": 15000,
        "their_min": 12000, "their_max": 18000,
    }
    scenario_no_deal = {
        "our_min": 10000, "our_max": 11000,
        "their_min": 12000, "their_max": 18000,
    }
    result_deal = engine.simulate_outcome(scenario_deal)
    result_no_deal = engine.simulate_outcome(scenario_no_deal)

    assert result_deal["outcome"] == "Deal is Possible"
    assert result_no_deal["outcome"] == "No Deal Likely"
