import numpy as np
from typing import List, Tuple, Dict, Any


class NegotiationEnv:
    """
    Defines the environment for the Reinforcement Learning agent.
    This includes the state space, action space, and reward function.
    """

    def __init__(self):
        # States: [our_last_offer, their_last_offer, last_sentiment]

        self.state_space_shape = (3,)
        # Actions: 0=hold, 1=concede, 2=make_offer

        self.action_space_n = 3

    def get_state_from_history(self, history: List[Dict[str, Any]]) -> np.ndarray:
        """Converts negotiation history into a state vector."""
        our_offers = [
            msg.get("analysis", {}).get("offer_amount")
            for msg in history
            if msg.get("sender_id") == "ai_negotiator"
            and msg.get("analysis", {}).get("offer_amount")
        ]
        their_offers = [
            msg.get("analysis", {}).get("offer_amount")
            for msg in history
            if msg.get("sender_id") != "ai_negotiator"
            and msg.get("analysis", {}).get("offer_amount")
        ]
        last_sentiment = (
            history[-1].get("analysis", {}).get("tone_score", 0) if history else 0
        )

        our_last_offer = our_offers[-1] if our_offers else 0
        their_last_offer = their_offers[-1] if their_offers else 0

        return np.array([our_last_offer, their_last_offer, last_sentiment])

    def get_reward(self, history: List[Dict[str, Any]], action: int) -> float:
        """Calculates the reward based on the outcome of an action."""
        if not history:
            return 0
        last_intent = history[-1].get("analysis", {}).get("intent")
        if last_intent == "acceptance":
            return 100.0  # High reward for successful deal
        if last_intent == "rejection":
            return -50.0  # Penalty for rejection
        # Small penalty for conceding to encourage holding firm

        if action == 1:  # Concede
            return -5.0
        return 1.0  # Small reward for continuing the negotiation
