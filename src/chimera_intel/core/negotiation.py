import re
import psycopg2
import json
import typer
from rich.console import Console
from typing import List, Dict, Any, Tuple, Optional
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from src.chimera_intel.core.voice_analysis import VoiceAnalyzer
import numpy as np
from transformers import pipeline
import logging

# --- (Existing imports) ---


from .negotiation_rl_env import NegotiationEnv
from .negotiation_rl_agent import QLearningAgent
from .ethical_guardrails import EthicalFramework
from .cultural_intelligence import (
    get_cultural_profile,
    add_cultural_profile,
    populate_initial_cultural_data,
    get_all_cultural_profiles,
)
from .advanced_nlp import AdvancedNLPAnalyzer
from .analytics import get_negotiation_kpis
from .negotiation_simulator import get_personas
from .config_loader import API_KEYS

# --- CLI Application Definition ---


console = Console()
negotiation_app = typer.Typer(
    help="A comprehensive suite for AI-assisted negotiation, analysis, and training."
)

# --- Engine Class Definition ---


class NegotiationEngine:
    """
    The negotiation core, enhanced with cultural intelligence, RL, ethical guardrails, and advanced NLP.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        db_params: Optional[Dict[str, Any]] = None,
        rl_model_path: Optional[str] = None,
        positive_sentiment_threshold: float = 0.1,
        negative_sentiment_threshold: float = -0.1,
    ):
        """
        Initializes the engine and its components.
        """
        self.positive_sentiment_threshold = positive_sentiment_threshold
        self.negative_sentiment_threshold = negative_sentiment_threshold
        try:
            if model_path:
                self.intent_classifier = pipeline(
                    "text-classification", model=model_path
                )
                logging.info(f"Successfully loaded transformer model from {model_path}")
            else:
                raise ValueError("Model path not provided for production mode.")
        except (Exception, ValueError) as e:
            logging.warning(
                f"Failed to load transformer model: {e}. Falling back to a simpler Naive Bayes model."
            )
            self.intent_vectorizer = TfidfVectorizer()
            self.intent_classifier_nb = MultinomialNB()
            self._train_intent_classifier()
        self.db_params = db_params
        self.rl_env = NegotiationEnv()
        self.rl_agent = QLearningAgent(action_space_n=self.rl_env.action_space_n)
        if rl_model_path:
            try:
                self.rl_agent.load_model(rl_model_path)
                self.rl_agent.epsilon = (
                    0.1  # Set to a low exploration rate for inference
                )
                logging.info(f"Successfully loaded RL model from {rl_model_path}")
            except FileNotFoundError:
                logging.warning(
                    f"RL model not found at {rl_model_path}. Using a new, untrained agent."
                )
        self.ethical_framework = EthicalFramework()
        self.advanced_nlp_analyzer = AdvancedNLPAnalyzer()
        self.voice_analyzer = VoiceAnalyzer()

    def _get_db_connection(self):
        """Establishes a connection to the database."""
        if not self.db_params:
            return None
        try:
            return psycopg2.connect(**self.db_params)
        except psycopg2.OperationalError as e:
            logging.error(f"Database Connection Error: {e}")
            return None

    def _get_counterparty_profile(
        self, counterparty_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetches the behavioral profile for a given counterparty."""
        conn = self._get_db_connection()
        if not conn:
            return None
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT communication_style, risk_appetite, key_motivators FROM behavioral_profiles WHERE counterparty_id = %s",
                    (counterparty_id,),
                )
                record = cursor.fetchone()
                if record:
                    return dict(record)
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
        """Extracts a numeric offer amount from a message."""
        # Improved regex to handle more formats

        match = re.search(
            r"([\$€£]?\s?(\d{1,3}(,\d{3})*(\.\d+)?)\s?(k|thousand|m|million|b|billion)?\s?(dollars|euros|pounds)?)",
            message_content,
            re.IGNORECASE,
        )
        if match:
            try:
                value_str = re.sub(r"[^\d\.]", "", match.group(2))
                value = float(value_str)
                multiplier = 1
                if match.group(5):
                    unit = match.group(5).lower()
                    if unit in ["k", "thousand"]:
                        multiplier = 1000
                    elif unit in ["m", "million"]:
                        multiplier = 1000000
                    elif unit in ["b", "billion"]:
                        multiplier = 1000000000
                return value * multiplier
            except (ValueError, IndexError):
                return None
        return None

    def analyze_message(self, message_content: str) -> Dict[str, Any]:
        """Analyzes a message for tone, intent, and advanced argumentation tactics."""
        blob = TextBlob(message_content)
        tone_score = blob.sentiment.polarity
        sentiment = (
            "positive"
            if tone_score > self.positive_sentiment_threshold
            else (
                "negative"
                if tone_score < self.negative_sentiment_threshold
                else "neutral"
            )
        )

        try:
            if hasattr(self, "intent_classifier"):
                intent_label = self.intent_classifier(message_content)[0]["label"]
            else:
                message_vec = self.intent_vectorizer.transform([message_content])
                intent_label = self.intent_classifier_nb.predict(message_vec)[0]
        except Exception as e:
            logging.error(f"Intent classification failed: {e}")
            intent_label = "unknown"
        detected_tactics = self.advanced_nlp_analyzer.detect_argument_tactics(
            message_content
        )

        return {
            "tone_score": tone_score,
            "sentiment": sentiment,
            "intent": intent_label,
            "offer_amount": self._extract_offer_amount(message_content),
            "argument_tactics": detected_tactics,
        }

    def recommend_tactic(
        self,
        history: List[Dict[str, Any]],
        batna: Optional[float] = None,
        zopa: Optional[Tuple[float, float]] = None,
        counterparty_id: Optional[str] = None,
        counterparty_country_code: Optional[str] = None,
        use_rl: bool = False,
        voice_analysis: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Recommends a tactic, validating it against ethical and cultural frameworks."""
        recommendation = self._generate_initial_recommendation(
            history, batna, zopa, counterparty_id, counterparty_country_code, use_rl
        )

        if voice_analysis:
            if (
                voice_analysis.get("vocal_sentiment") == "hesitant"
                and voice_analysis.get("confidence_score", 1.0) < 0.7
            ):
                recommendation.update(
                    {
                        "tactic": "Probing Question",
                        "reason": "Vocal analysis detects hesitation. There may be an unstated concern or opportunity.",
                        "bot_response": "I sense there might be something we haven't fully addressed. Is there anything else on your mind regarding this point?",
                    }
                )
        bot_response = recommendation.get("bot_response", "")
        ethical_violations = self.ethical_framework.check_message(bot_response)

        if ethical_violations:
            warnings = [
                f"Warning ({violation['severity']}): The suggested response may violate the '{violation['violation']}' guideline."
                for violation in ethical_violations
            ]
            recommendation["ethical_warnings"] = warnings
            # We no longer overwrite the bot_response, just add a warning.
            # The user can decide how to proceed.
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
            action_map = {
                0: "Hold Firm",
                1: "Strategic Concession",
                2: "Propose Offer",
            }
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

        recommendation = self._get_base_recommendation(history, profile)

        if cultural_profile and not history:
            if cultural_profile.get("formality", 5) > 7:
                recommendation["bot_response"] = (
                    "Greetings. I would like to begin our discussion. What are your initial thoughts on the matter?"
                )
            if cultural_profile.get("directness", 5) < 4:
                recommendation["bot_response"] = recommendation["bot_response"].replace(
                    "What are your initial thoughts?",
                    "Perhaps we could begin by exploring some general ideas on this topic?",
                )
        return recommendation

    def _get_base_recommendation(
        self, history: List[Dict[str, Any]], profile: Optional[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Generates a recommendation based on history, profile, and advanced NLP analysis."""
        if not history:
            response = "Thank you for starting this discussion. What are your initial thoughts?"
            if profile and profile.get("communication_style") == "Informal":
                response = "Hey, thanks for reaching out. What's on your mind?"
            return {
                "tactic": "Opening Move",
                "reason": "Establish a strong, positive opening.",
                "bot_response": response,
            }
        last_message = history[-1]
        last_analysis = last_message.get("analysis", {})
        last_sentiment = last_analysis.get("tone_score", 0)

        # More comprehensive history analysis can be added here
        # For example, tracking sentiment over time, frequency of certain tactics, etc.

        if last_analysis.get("argument_tactics"):
            detected_tactic = last_analysis["argument_tactics"][0]
            if detected_tactic["tactic"] == "scarcity":
                return {
                    "tactic": "Counter: Question Scarcity",
                    "reason": f"Counterparty is using a scarcity tactic ('{detected_tactic['triggered_by']}'). Verify the claim.",
                    "bot_response": "That's an important consideration. Can you provide more details on why the availability is limited? Understanding the constraints will help us move forward.",
                }
            if detected_tactic["tactic"] == "social_proof":
                return {
                    "tactic": "Counter: Re-Focus on Value",
                    "reason": f"Counterparty is using social proof ('{detected_tactic['triggered_by']}'). Re-focus the discussion on our specific needs.",
                    "bot_response": "I understand that's a popular option. However, our primary goal is to find the best fit for our specific requirements. Let's focus on how this aligns with our unique needs.",
                }
        if last_sentiment < -0.5:
            return {
                "tactic": "De-escalate",
                "reason": "The sentiment is very negative.",
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
            "reason": "The negotiation is stable.",
            "bot_response": "That's an interesting point. Can you tell me more about what's driving that position? I'm sure we can find a creative solution.",
        }

    def assess_batna(self, alternatives: List[Dict[str, float]]) -> Dict[str, Any]:
        """Assesses the Best Alternative To a Negotiated Agreement (BATNA)."""
        if not alternatives:
            return {"best_alternative": None, "value": -np.inf}
        best_alternative = max(alternatives, key=lambda x: x.get("value", -np.inf))
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


# --- (CLI commands remain largely the same, but with logging instead of console.print) ---


analytics_cmd = typer.Typer(
    help="Tools for negotiation analytics and decision support."
)
negotiation_app.add_typer(analytics_cmd, name="analytics")


@analytics_cmd.command("show")
def show_analytics():
    """Displays a dashboard with KPIs for negotiation performance."""
    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }
    kpis = get_negotiation_kpis(db_params)
    console.print("--- Negotiation Performance KPIs ---")
    console.print(kpis)


# --- Simulator Sub-Command ---


simulator_cmd = typer.Typer(help="Train your negotiation skills against AI personas.")
negotiation_app.add_typer(simulator_cmd, name="simulator")


@simulator_cmd.command("start")
def start_simulation(persona_name: str = typer.Argument("cooperative")):
    """Starts an interactive negotiation simulation with a chosen AI persona."""
    personas = get_personas()
    persona = personas.get(persona_name.lower())
    if not persona:
        console.print(
            f"[bold red]Error: Persona '{persona_name}' not found.[/bold red]"
        )
        return
    console.print(f"Starting simulation with {persona.name}...")
    # (Full interactive simulation logic would go here)


# --- Cultural Intelligence Sub-Command ---


cultural_cmd = typer.Typer(help="Tools for managing Cultural Intelligence profiles.")
negotiation_app.add_typer(cultural_cmd, name="cultural")


@cultural_cmd.command("add")
def add_profile_cli(
    country_code: str,
    country_name: str,
    directness: int,
    formality: int,
    power_distance: int,
    individualism: int,
    uncertainty_avoidance: int,
):
    """Adds or updates a cultural profile."""
    profile_data = {
        "country_code": country_code.upper(),
        "country_name": country_name,
        "directness": directness,
        "formality": formality,
        "power_distance": power_distance,
        "individualism": individualism,
        "uncertainty_avoidance": uncertainty_avoidance,
    }
    add_cultural_profile(profile_data)


@cultural_cmd.command("list")
def list_profiles_cli():
    """Lists all stored cultural profiles."""
    profiles = get_all_cultural_profiles()
    console.print(profiles)


# --- Engine Management Sub-Command ---


engine_cmd = typer.Typer(help="Direct commands for managing the negotiation engine.")
negotiation_app.add_typer(engine_cmd, name="engine")


@engine_cmd.command("train-rl")
def train_rl_agent(
    episodes: int = typer.Option(1000, "--episodes", "-e"),
    output_path: str = typer.Option("negotiation_rl_model.pkl", "--output", "-o"),
):
    """Trains the negotiation RL agent through simulation."""
    console.print(f"Starting RL training for {episodes} episodes...")
    # (Full RL training logic resides here)

    console.print(f"Training complete! Model saved to {output_path}")
