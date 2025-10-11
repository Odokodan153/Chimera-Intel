import numpy as np
from typing import List, Dict, Any, Tuple


class NegotiationEnv:
    """
    An enhanced negotiation environment for the RL agent.
    """

    def __init__(
        self,
        opponent_persona: Dict[str, Any] = None,
        zopa: Tuple[float, float] = (8000, 12000),
    ):
        """
        Initializes the environment with an optional opponent persona.
        """
        self.action_space_n = (
            3  # 0: Hold Firm, 1: Strategic Concession, 2: Propose Offer
        )
        self.zopa = zopa  # Zone of Possible Agreement (ZOPA)
        self.max_turns = 25  # Maximum number of turns before the negotiation is considered to have reached an impasse.
        self.state_size = 7  # The size of the state vector
        self.reward_weights = {
            "deal": 15,
            "rejection": -7,
            "sentiment": 2,
            "convergence": 1,
            "negativity": -2,
            "ethical": -15,
        }

        if opponent_persona is None:
            self.opponent_persona = {"name": "neutral", "risk_appetite": "medium"}
        else:
            self.opponent_persona = opponent_persona

    def reset(self):
        """Resets the environment for a new episode."""
        self.min_sentiment_trend = -2
        self.max_sentiment_trend = 2
        return np.zeros(self.state_size)

    def _normalize(self, value: float, min_val: float, max_val: float) -> float:
        """Normalizes a value to the 0-1 range."""
        if max_val == min_val:
            return 0.0
        return (value - min_val) / (max_val - min_val + 1e-8)

    def get_state_from_history(
        self, history: List[Dict[str, Any]], last_n_turns: int = 3
    ) -> np.ndarray:
        """
        Generates a normalized state vector from the negotiation history.
        """
        if not history:
            return np.zeros(self.state_size)
        our_offers = [
            msg["analysis"].get("offer_amount", 0)
            for msg in history
            if msg.get("sender_id") == "ai_negotiator"
        ]
        their_offers = [
            msg["analysis"].get("offer_amount", 0)
            for msg in history
            if msg.get("sender_id") == "them"
        ]
        sentiments = [msg["analysis"].get("tone_score", 0) for msg in history]

        # --- Feature Calculation ---

        avg_our_offer = np.mean(our_offers[-last_n_turns:]) if our_offers else 0
        avg_their_offer = np.mean(their_offers[-last_n_turns:]) if their_offers else 0
        avg_sentiment = np.mean(sentiments[-last_n_turns:]) if sentiments else 0
        sentiment_trend = sentiments[-1] - sentiments[0] if len(sentiments) > 1 else 0
        turn_count = len(history)
        offer_std_dev = np.std(their_offers[-last_n_turns:]) if their_offers else 0
        last_offer_diff = (
            abs(our_offers[-1] - their_offers[-1]) if our_offers and their_offers else 0
        )

        # --- Dynamic sentiment trend normalization ---

        self.max_sentiment_trend = max(self.max_sentiment_trend, sentiment_trend)
        self.min_sentiment_trend = min(self.min_sentiment_trend, sentiment_trend)

        # --- Normalization ---

        norm_our_offer = self._normalize(avg_our_offer, self.zopa[0], self.zopa[1])
        norm_their_offer = self._normalize(avg_their_offer, self.zopa[0], self.zopa[1])
        norm_sentiment = self._normalize(avg_sentiment, -1, 1)
        norm_sentiment_trend = self._normalize(
            sentiment_trend, self.min_sentiment_trend, self.max_sentiment_trend
        )
        norm_turn_count = turn_count / self.max_turns
        norm_offer_std_dev = self._normalize(
            offer_std_dev, 0, (self.zopa[1] - self.zopa[0]) / 2
        )
        norm_last_offer_diff = self._normalize(
            last_offer_diff, 0, self.zopa[1] - self.zopa[0]
        )

        return np.array(
            [
                norm_our_offer,
                norm_their_offer,
                norm_sentiment,
                norm_sentiment_trend,
                norm_turn_count,
                norm_offer_std_dev,
                norm_last_offer_diff,
            ]
        )

    def get_reward(self, history: List[Dict[str, Any]], action: int) -> float:
        """
        Calculates the reward based on the outcome of an action.
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
                reward += (
                    self.reward_weights["deal"]
                    + (last_offer - self.zopa[0]) / (self.zopa[1] - self.zopa[0]) * 5
                )
            else:
                reward += self.reward_weights["rejection"]
        elif intent == "rejection":
            reward += self.reward_weights["rejection"]
        # Continuous reward shaping for sentiment

        tone_score = analysis.get("tone_score", 0)
        reward += tone_score * self.reward_weights["sentiment"]

        # Reward for offer convergence

        if len(history) > 1:
            our_offers = [
                msg.get("analysis", {}).get("offer_amount", 0)
                for msg in history
                if msg.get("sender_id") == "ai_negotiator"
            ]
            their_offers = [
                msg.get("analysis", {}).get("offer_amount", 0)
                for msg in history
                if msg.get("sender_id") == "them"
            ]
            if len(our_offers) > 0 and len(their_offers) > 0:
                avg_our_offer = np.mean(our_offers[-3:])
                avg_their_offer = np.mean(their_offers[-3:])
                reward += (
                    1
                    - self._normalize(
                        abs(avg_our_offer - avg_their_offer),
                        0,
                        self.zopa[1] - self.zopa[0],
                    )
                ) * self.reward_weights["convergence"]
        # Penalize consecutive negative sentiment

        if (
            len(history) > 1
            and history[-1].get("analysis", {}).get("sentiment") == "negative"
            and history[-2].get("analysis", {}).get("sentiment") == "negative"
        ):
            reward += self.reward_weights["negativity"]
        if analysis.get("ethical_violations"):
            reward += self.reward_weights["ethical"]
        return reward

    def is_done(self, history: List[Dict[str, Any]]) -> bool:
        """
        Determines if the negotiation episode has concluded.
        """
        if not history:
            return False
        last_message = history[-1]
        analysis = last_message.get("analysis", {})
        intent = analysis.get("intent", "unknown")

        if intent in ["acceptance", "rejection"]:
            return True
        if len(history) > self.max_turns:
            return True
        return False
