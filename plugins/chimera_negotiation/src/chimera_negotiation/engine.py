import re
import psycopg2
import json
from typing import List, Dict, Any, Tuple, Optional
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np
from transformers import pipeline
import logging
from chimera_intel.core.negotiation_rl_env import NegotiationEnv
from chimera_intel.core.negotiation_rl_agent import QLearningAgent
from chimera_intel.core.ethical_guardrails import EthicalFramework
from chimera_intel.core.cultural_intelligence import get_cultural_profile

# Configure logging for production readiness

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class NegotiationEngine:
    """
    The negotiation core, now enhanced with cultural intelligence, RL, and ethical guardrails.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        db_params: Optional[Dict[str, Any]] = None,
        rl_model_path: Optional[str] = None,
    ):
        """
        Initializes the engine and its components.
        Args:
            model_path (Optional[str]): Path to a pre-trained transformer model.
            db_params (Optional[Dict[str, Any]]): Database connection parameters.
            rl_model_path (Optional[str]): Path to a pre-trained reinforcement learning model.
        """
        try:
            if model_path:
                self.intent_classifier = pipeline(
                    "text-classification", model=model_path
                )
                logger.info(f"Successfully loaded transformer model from {model_path}")
            else:
                raise ValueError("Model path not provided for production mode.")
        except (Exception, ValueError) as e:
            logger.warning(
                f"Failed to load transformer model: {e}. Falling back to a simpler Naive Bayes model."
            )
            self.intent_vectorizer = TfidfVectorizer()
            self.intent_classifier_nb = MultinomialNB()
            self._train_intent_classifier()
        self.db_params = db_params

        # Initialize RL components

        self.rl_env = NegotiationEnv()
        self.rl_agent = QLearningAgent(action_space_n=self.rl_env.action_space_n)
        if rl_model_path:
            try:
                self.rl_agent.load_model(rl_model_path)
                self.rl_agent.epsilon = 0.1  # In production, reduce exploration
                logger.info(f"Successfully loaded RL model from {rl_model_path}")
            except FileNotFoundError:
                logger.warning(
                    f"RL model not found at {rl_model_path}. Using a new, untrained agent."
                )
        # Initialize Ethical Framework

        self.ethical_framework = EthicalFramework()

    def _get_db_connection(self):
        """Establishes a connection to the database."""
        if not self.db_params:
            return None
        try:
            return psycopg2.connect(**self.db_params)
        except psycopg2.OperationalError as e:
            logger.error(f"Database Connection Error: {e}")
            return None

    def _get_counterparty_profile(
        self, counterparty_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetches the behavioral profile for a given counterparty."""
        conn = self._get_db_connection()
        if not conn:
            return None
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT communication_style, risk_appetite, key_motivators FROM behavioral_profiles WHERE counterparty_id = %s",
                    (counterparty_id,),
                )
                record = cursor.fetchone()
                if record:
                    return {
                        "communication_style": record[0],
                        "risk_appetite": record[1],
                        "key_motivators": record[2],
                    }
            return None
        finally:
            if conn:
                conn.close()

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
            logger.error(f"Intent classification failed: {e}")
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
        counterparty_id: Optional[str] = None,
        counterparty_country_code: Optional[str] = None,
        use_rl: bool = False,
    ) -> Dict[str, str]:
        """
        Recommends a tactic, validating it against ethical and cultural frameworks.
        """
        recommendation = self._generate_initial_recommendation(
            history, batna, zopa, counterparty_id, counterparty_country_code, use_rl
        )

        # Ethical Check on the bot's own suggested response

        bot_response = recommendation.get("bot_response", "")
        ethical_check = self.ethical_framework.check_message(bot_response)

        if ethical_check:
            recommendation["ethical_warning"] = (
                f"Warning ({ethical_check['severity']}): "
                f"The suggested response may violate the '{ethical_check['violation']}' guideline. "
                f"Reason: {ethical_check['description']}"
            )
            # As a safeguard, replace the response with a neutral one

            recommendation["bot_response"] = (
                "Let's re-evaluate. What would be a fair path forward?"
            )
        return recommendation

    def _generate_initial_recommendation(
        self,
        history: List[Dict[str, Any]],
        batna: Optional[float],
        zopa: Optional[Tuple[float, float]],
        counterparty_id: Optional[str],
        counterparty_country_code: Optional[str],
        use_rl: bool,
    ) -> Dict[str, str]:
        """Helper method to contain the original recommendation logic."""
        if use_rl:
            state = self.rl_env.get_state_from_history(history)
            action = self.rl_agent.choose_action(state)
            action_map = {0: "Hold Firm", 1: "Strategic Concession", 2: "Propose Offer"}
            return {
                "tactic": f"RL: {action_map.get(action, 'Unknown')}",
                "reason": "Recommendation from the trained reinforcement learning agent.",
                "bot_response": "Let me consider the best path forward based on my learned strategies.",
            }
        profile = (
            self._get_counterparty_profile(counterparty_id) if counterparty_id else None
        )
        cultural_profile = (
            get_cultural_profile(counterparty_country_code)
            if counterparty_country_code
            else None
        )

        # Base recommendation

        recommendation = self._get_base_recommendation(history, profile)

        # Cultural Adaptation Layer

        if cultural_profile:
            # Adapt for formality

            if cultural_profile.get("formality", 5) > 7 and not history:
                recommendation["bot_response"] = (
                    "Greetings. I would like to begin our discussion. What are your initial thoughts on the matter?"
                )
            # Adapt for directness

            if (
                cultural_profile.get("directness", 5) < 4 and not history
            ):  # Indirect culture
                recommendation["bot_response"] = recommendation["bot_response"].replace(
                    "What are your initial thoughts?",
                    "Perhaps we could begin by exploring some general ideas on this topic?",
                )
        return recommendation

    def _get_base_recommendation(
        self, history: List[Dict[str, Any]], profile: Optional[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Generates a recommendation based on history and behavioral profile."""
        if not history:
            response = "Thank you for starting this discussion. I'm looking forward to finding a mutually beneficial agreement. What are your initial thoughts?"
            if profile and profile.get("communication_style") == "Informal":
                response = "Hey, thanks for reaching out. Excited to see what we can work out. What's on your mind?"
            return {
                "tactic": "Opening Move",
                "reason": "This is the first move. Establish a strong, positive opening.",
                "bot_response": response,
            }
        last_message = history[-1]
        last_sentiment = last_message.get("analysis", {}).get("tone_score", 0)

        if last_sentiment < -0.5:
            return {
                "tactic": "De-escalate",
                "reason": "The sentiment is very negative. It's important to de-escalate the situation.",
                "bot_response": "I understand your concerns. Let's take a step back and see if we can find some common ground.",
            }
        if profile and profile.get("risk_appetite") == "Risk-seeking":
            return {
                "tactic": "Propose High-Growth Option",
                "reason": "Counterparty is risk-seeking. Propose a high-reward scenario.",
                "bot_response": "Considering your focus on growth, what if we explored a more ambitious partnership with a higher potential upside for both of us?",
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
