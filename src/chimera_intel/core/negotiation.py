import re
from typing import List, Dict, Any, Tuple, Optional
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np
import joblib
from transformers import pipeline
import logging

# Configure logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class NegotiationEngine:
    """
    A unified negotiation core that includes ML analysis, economic assessment,
    context-aware recommendations, and outcome simulation. It can now also
    generate bot responses to act as an AI negotiator.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initializes the engine.
        Args:
            model_path (Optional[str]): Path to a pre-trained transformer model.
                                       If None, a placeholder model is trained.
        """
        self.message_history = []
        try:
            if model_path:
                # In production, load a fine-tuned transformer model

                self.intent_classifier = pipeline(
                    "text-classification", model=model_path
                )
                logger.info(f"Successfully loaded transformer model from {model_path}")
            else:
                raise ValueError("Model path not provided.")
        except (Exception, ValueError) as e:
            logger.warning(
                f"Failed to load transformer model: {e}. Falling back to Naive Bayes."
            )
            # For development, we use a simple placeholder

            self.intent_vectorizer = TfidfVectorizer()
            self.intent_classifier_nb = MultinomialNB()
            self._train_intent_classifier()

    def _train_intent_classifier(self):
        """Trains a simple Naive Bayes classifier for intent detection."""
        training_data = [
            ("I can offer $5,000.", "offer"),
            ("We need this delivered by next week.", "condition"),
            ("That is too high.", "rejection"),
            ("Let's discuss the terms.", "discussion"),
            ("I agree to your proposal.", "acceptance"),
        ]
        X, y = zip(*training_data)
        X_vec = self.intent_vectorizer.fit_transform(X)
        self.intent_classifier_nb.fit(X_vec, y)

    def _extract_offer_amount(self, message_content: str) -> Optional[float]:
        """Extracts a numeric offer amount from a message, handling various formats."""
        # Handles formats like $5,000, 5k, €5000, 5000 dollars

        match = re.search(
            r"[\$€£]?\s?(\d{1,3}(,\d{3})*(\.\d+)?)\s?(k|thousand|million|billion)?\s?(dollars|euros|pounds)?",
            message_content,
            re.IGNORECASE,
        )
        if match:
            try:
                value = float(match.group(1).replace(",", ""))
                multiplier = 1
                if match.group(4):
                    if match.group(4).lower() in ["k", "thousand"]:
                        multiplier = 1000
                    elif match.group(4).lower() == "million":
                        multiplier = 1000000
                    elif match.group(4).lower() == "billion":
                        multiplier = 1000000000
                return value * multiplier
            except (ValueError, IndexError):
                return None
        return None

    def analyze_message(self, message_content: str) -> Dict[str, Any]:
        """Analyzes a single message for tone, sentiment, intent, and offer amount."""
        blob = TextBlob(message_content)
        tone_score = blob.sentiment.polarity
        sentiment = (
            "positive"
            if tone_score > 0.1
            else "negative" if tone_score < -0.1 else "neutral"
        )

        try:
            if hasattr(self, "intent_classifier"):
                intent_label = self.intent_classifier(message_content)[0]["label"]
            else:
                message_vec = self.intent_vectorizer.transform([message_content])
                intent_label = self.intent_classifier_nb.predict(message_vec)[0]
        except Exception as e:
            logger.error(f"Failed to predict intent: {e}")
            intent_label = "unknown"
        analysis = {
            "tone_score": tone_score,
            "sentiment": sentiment,
            "intent": intent_label,
            "offer_amount": self._extract_offer_amount(message_content),
        }
        return analysis

    def recommend_tactic(
        self,
        history: List[Dict[str, Any]],
        batna: Optional[float] = None,
        zopa: Optional[Tuple[float, float]] = None,
    ) -> Dict[str, str]:
        """Recommends a tactic and generates a bot response based on the negotiation history."""
        if not history:
            return {
                "tactic": "Opening Move",
                "reason": "This is the first move. Establish a strong, positive opening.",
                "bot_response": "Thank you for starting this discussion. I'm looking forward to finding a mutually beneficial agreement. What are your initial thoughts?",
            }
        last_message = history[-1]
        last_sentiment = last_message.get("analysis", {}).get("tone_score", 0)
        offers = [
            msg.get("analysis", {}).get("offer_amount")
            for msg in history
            if msg.get("analysis", {}).get("intent") == "offer"
            and msg.get("analysis", {}).get("offer_amount") is not None
        ]

        if last_sentiment < -0.5:
            return {
                "tactic": "De-escalate",
                "reason": "The sentiment is very negative. It's important to de-escalate the situation.",
                "bot_response": "I understand your concerns. Let's take a step back and see if we can find some common ground.",
            }
        if zopa and offers and offers[-1] < zopa[0]:
            return {
                "tactic": "Anchor to BATNA",
                "reason": f"The last offer is below the viable zone. Re-anchor the conversation to your BATNA.",
                "bot_response": f"I appreciate the offer, but that's not in the range we're looking for. To be transparent, we have an alternative valued at ${batna}. Can we work from there?",
            }
        return {
            "tactic": "Collaborative Exploration",
            "reason": "The negotiation is stable. Time to explore options.",
            "bot_response": "That's an interesting point. Can you tell me more about what's driving that position? I'm sure we can find a creative solution.",
        }

    def assess_batna(self, alternatives: List[Dict[str, float]]) -> Dict[str, Any]:
        """Assesses the Best Alternative To a Negotiated Agreement (BATNA)."""
        if not alternatives:
            return {"best_alternative": None, "value": -np.inf}
        best_alternative = max(alternatives, key=lambda x: x["value"])
        return {"best_alternative": best_alternative}

    def calculate_zopa(
        self, our_min: float, our_max: float, their_min: float, their_max: float
    ) -> Optional[Tuple[float, float]]:
        """Calculates the Zone of Possible Agreement (ZOPA)."""
        zopa_start = max(our_min, their_min)
        zopa_end = min(our_max, their_max)
        return (zopa_start, zopa_end) if zopa_start < zopa_end else None

    def simulate_outcome(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates a negotiation outcome using a Monte Carlo method."""
        num_simulations = 1000
        # Use provided scenario data, with fallbacks for safety

        our_min = scenario.get("our_min", 0)
        our_max = scenario.get("our_max", 10000)
        their_min = scenario.get("their_min", 0)
        their_max = scenario.get("their_max", 10000)

        successful_deals = sum(
            1
            for _ in range(num_simulations)
            if np.random.uniform(our_min, our_max)
            >= np.random.uniform(their_min, their_max)
        )

        return {"success_probability": successful_deals / num_simulations}
