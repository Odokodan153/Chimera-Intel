import numpy as np
from typing import List, Dict, Any, Tuple


class NegotiationEnv:
    """
    An enhanced negotiation environment for the RL agent.
    """

    def __init__(self, opponent_persona: Dict[str, Any] = None):
        """
        Initializes the environment with an optional opponent persona.
        """
        self.action_space_n = (
            3  # 0: Hold Firm, 1: Strategic Concession, 2: Propose Offer
        )
        self.zopa = (8000, 12000)  # Example Zone of Possible Agreement (ZOPA)

        if opponent_persona is None:
            self.opponent_persona = {"name": "neutral", "risk_appetite": "medium"}
        else:
            self.opponent_persona = opponent_persona

    def get_state_from_history(
        self, history: List[Dict[str, Any]], last_n_turns: int = 3
    ) -> np.ndarray:
        """
        Generates a state vector from the negotiation history.

        The state vector is designed to capture the recent dynamics of the negotiation, including:
        - Rolling average of the last N offers from both the AI and the opponent.
        - Rolling average of the sentiment scores from the last N messages.
        - The trend of the sentiment (e.g., is the conversation becoming more positive or negative?).
        - The total number of turns, to track the length of the negotiation.
        """
        if not history:
            return np.zeros(5)
        # Extract recent offers and sentiments for trend analysis

        our_offers = [
            msg["analysis"].get("offer_amount", 0)
            for msg in history[-last_n_turns:]
            if msg.get("sender_id") == "ai_negotiator"
        ]
        their_offers = [
            msg["analysis"].get("offer_amount", 0)
            for msg in history[-last_n_turns:]
            if msg.get("sender_id") == "them"
        ]
        sentiments = [
            msg["analysis"].get("tone_score", 0) for msg in history[-last_n_turns:]
        ]

        # Calculate features for the state vector

        avg_our_offer = np.mean(our_offers) if our_offers else 0
        avg_their_offer = np.mean(their_offers) if their_offers else 0
        avg_sentiment = np.mean(sentiments) if sentiments else 0
        sentiment_trend = sentiments[-1] - sentiments[0] if len(sentiments) > 1 else 0
        turn_count = len(history)

        return np.array(
            [avg_our_offer, avg_their_offer, avg_sentiment, sentiment_trend, turn_count]
        )

    def get_reward(self, history: List[Dict[str, Any]], action: int) -> float:
        """
        Calculates the reward based on the outcome of an action.

        The reward function is designed to encourage desirable negotiation behaviors, such as:
        - Reaching a deal within the Zone of Possible Agreement (ZOPA).
        - Maintaining a positive sentiment throughout the negotiation.
        - Avoiding unethical tactics.
        """
        if not history:
            return 0
        last_message = history[-1]
        analysis = last_message.get("analysis", {})
        intent = analysis.get("intent", "unknown")
        reward = 0

        # Reward for successful deals within the ZOPA

        if intent == "acceptance":
            last_offer = analysis.get("offer_amount", 0)
            if self.zopa[0] <= last_offer <= self.zopa[1]:
                reward += 15  # Strong reward for a successful outcome
            else:
                reward -= 10  # Penalize deals outside the acceptable range
        # Penalize rejections to discourage unsuccessful tactics

        elif intent == "rejection":
            reward -= 7
        # Reward for positive sentiment, penalize negative sentiment

        if analysis.get("sentiment") == "positive":
            reward += 2
        elif analysis.get("sentiment") == "negative":
            reward -= 4  # Penalize negativity more heavily to encourage de-escalation
        # Penalize the use of unethical tactics

        if analysis.get("ethical_violations"):
            reward -= 15  # Strong penalty for unethical behavior
        return reward

    def is_done(self, history: List[Dict[str, Any]]) -> bool:
        """
        Determines if the negotiation episode has concluded.

        An episode ends if:
        - A deal is accepted or rejected.
        - The negotiation reaches an impasse (e.g., exceeds a maximum number of turns).
        """
        if not history:
            return False
        last_intent = history[-1].get("analysis", {}).get("intent", "unknown")
        if last_intent in ["acceptance", "rejection"]:
            return True
        if len(history) > 25:  # End after 25 turns to represent a potential impasse
            return True
        return False
