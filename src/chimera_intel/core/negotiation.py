from typing import List, Dict, Any, Tuple, Optional
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np
import joblib
from transformers import pipeline


class NegotiationEngine:
    """
    A unified negotiation core that includes ML analysis, economic assessment,
    context-aware recommendations, and outcome simulation.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initializes the engine.
        Args:
            model_path (Optional[str]): Path to a pre-trained transformer model.
                                       If None, a placeholder model is trained.
        """
        self.message_history = []
        if model_path:
            # In production, load a fine-tuned transformer model

            self.intent_classifier = pipeline("text-classification", model=model_path)
        else:
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

    def analyze_message(self, message_content: str) -> Dict[str, Any]:
        """Analyzes a single message for tone, sentiment, and intent."""
        blob = TextBlob(message_content)
        tone_score = blob.sentiment.polarity
        sentiment = (
            "positive"
            if tone_score > 0.1
            else "negative" if tone_score < -0.1 else "neutral"
        )

        if hasattr(self, "intent_classifier"):
            # Production-ready transformer model

            intent_label = self.intent_classifier(message_content)[0]["label"]
        else:
            # Placeholder Naive Bayes model

            message_vec = self.intent_vectorizer.transform([message_content])
            intent_label = self.intent_classifier_nb.predict(message_vec)[0]
        analysis = {
            "tone_score": tone_score,
            "sentiment": sentiment,
            "intent": intent_label,
        }
        self.message_history.append(analysis)
        return analysis

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

    def recommend_tactic(self, history: List[Dict[str, Any]]) -> Dict[str, str]:
        """Recommends a tactic based on the negotiation history."""
        if not history:
            return {
                "tactic": "Opening Move",
                "reason": "This is the first move. Establish a strong, positive opening and clearly state your primary interests.",
            }
        # Analyze the full history

        avg_sentiment = np.mean(
            [msg.get("analysis", {}).get("tone_score", 0) for msg in history]
        )
        last_message = history[-1]
        last_sentiment = last_message.get("analysis", {}).get("tone_score", 0)

        if last_sentiment < -0.5:
            return {
                "tactic": "Strategic Concession",
                "reason": f"The last message was highly negative (score: {last_sentiment:.2f}). A small concession could improve the climate.",
            }
        elif avg_sentiment < -0.2:
            return {
                "tactic": "Reframe the Conversation",
                "reason": f"The overall sentiment of the negotiation is negative (average: {avg_sentiment:.2f}). It's time to focus on shared interests.",
            }
        return {
            "tactic": "Collaborative Exploration",
            "reason": "The negotiation is stable. Focus on asking open-ended questions to uncover underlying interests and create mutual value.",
        }

    def simulate_outcome(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Simulates a negotiation outcome using a Monte Carlo method."""
        num_simulations = 1000
        successful_deals = sum(
            1
            for _ in range(num_simulations)
            if np.random.uniform(scenario["our_min"], scenario["our_max"])
            >= np.random.uniform(scenario["their_min"], scenario["their_max"])
        )

        return {"success_probability": successful_deals / num_simulations}
