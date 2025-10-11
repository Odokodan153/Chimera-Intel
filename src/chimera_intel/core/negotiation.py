import re
import psycopg2
import json
import typer
from rich.console import Console
from typing import List, Dict, Any, Tuple, Optional
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np
from transformers import pipeline
import logging

# --- Imports for LLM Integration ---

from .llm_interface import LLMInterface, MockLLMInterface
from .negotiation_rl_agent import QLearningLLMAgent, QLearningAgent
from .ethical_guardrails import EthicalFramework
from .cultural_intelligence import get_cultural_profile
from .advanced_nlp import AdvancedNLPAnalyzer
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
        db_params: Optional[Dict[str, Any]] = None,
        rl_model_path: Optional[str] = None,
        positive_sentiment_threshold: float = 0.1,
        negative_sentiment_threshold: float = -0.1,
        use_llm: bool = False,
        use_mock_llm: bool = False,
    ):
        """
        Initializes the engine and its components.
        """
        self.positive_sentiment_threshold = positive_sentiment_threshold
        self.negative_sentiment_threshold = negative_sentiment_threshold
        self.db_params = db_params
        self.ethical_framework = EthicalFramework()
        self.advanced_nlp_analyzer = AdvancedNLPAnalyzer()
        self.llm = None

        # Conditionally initialize the appropriate agent (LLM or standard)

        if use_llm:
            try:
                if use_mock_llm:
                    self.llm = MockLLMInterface()
                    logging.info("Using Mock LLM Interface for testing.")
                else:
                    self.llm = LLMInterface()
                    logging.info("Using live Gemini LLM Interface.")
                self.rl_agent = QLearningLLMAgent(
                    llm=self.llm,
                    ethics=self.ethical_framework,
                    db_params=self.db_params,
                    action_space_n=3,  # Corresponds to actions like "Generate Offer", "Generate Query", etc.
                )
                logging.info("Initialized with QLearningLLMAgent.")
            except ValueError as e:
                logging.error(
                    f"LLM Initialization Failed: {e}. Falling back to standard agent."
                )
                self.rl_agent = QLearningAgent(action_space_n=3)
        else:
            self.rl_agent = QLearningAgent(action_space_n=3)
            logging.info("Initialized with standard QLearningAgent.")
        # Load a pre-trained RL model if a path is provided

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

    def _get_db_connection(self):
        """Establishes a connection to the database."""
        if not self.db_params:
            logging.warning("Database parameters are not configured.")
            return None
        try:
            return psycopg2.connect(**self.db_params)
        except psycopg2.OperationalError as e:
            logging.error(f"Database Connection Error: {e}")
            return None

    def analyze_message(self, message_content: str) -> Dict[str, Any]:
        """Analyzes a message for sentiment and argumentation tactics."""
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
        detected_tactics = self.advanced_nlp_analyzer.detect_argument_tactics(
            message_content
        )
        return {
            "tone_score": tone_score,
            "sentiment": sentiment,
            "argument_tactics": detected_tactics,
        }

    def recommend_tactic(
        self,
        history: List[Dict[str, Any]],
        counterparty_country_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Selects a tactic and generates a response, using the LLM if available.
        """
        state_representation = self._get_state_from_history(history)

        # If using the LLM-powered agent, generate a dynamic response

        if isinstance(self.rl_agent, QLearningLLMAgent):
            bot_response = self.rl_agent.generate_negotiation_message(
                state_representation, counterparty_country_code
            )
            self._log_llm_interaction(
                state_representation, bot_response, counterparty_country_code
            )
            return {
                "tactic": "LLM-Generated Response",
                "reason": "Dynamically generated by the language model based on the negotiation context.",
                "bot_response": bot_response,
            }
        # Fallback to a simple rule-based recommendation if not using the LLM

        return self._generate_rule_based_recommendation(history)

    def _get_state_from_history(self, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Creates a state summary from the message history for the LLM."""
        if not history:
            return {"status": "Start of negotiation"}
        last_message = history[-1]
        analysis = last_message.get("analysis", {})
        return {
            "last_message_content": last_message.get("content", ""),
            "last_message_sentiment": analysis.get("sentiment", "neutral"),
            "detected_tactics_in_last_message": [
                t["tactic"] for t in analysis.get("argument_tactics", [])
            ],
            "negotiation_turn_number": len(history),
        }

    def _log_llm_interaction(
        self, state: Dict[str, Any], response: str, country_code: Optional[str]
    ):
        """Logs the LLM interaction details to the database."""
        conn = self._get_db_connection()
        if not conn or not isinstance(self.rl_agent, QLearningLLMAgent):
            return
        cultural_profile = get_cultural_profile(country_code) if country_code else {}
        ethical_violations = self.ethical_framework.check_message(response)

        # Construct a readable prompt for logging purposes

        prompt_for_log = f"State: {json.dumps(state)}, Cultural Profile: {json.dumps(cultural_profile)}"

        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO llm_logs (model_name, prompt, response, ethical_flags, cultural_context)
                    VALUES (%s, %s, %s, %s, %s);
                """,
                    (
                        (
                            self.llm.model.model_name
                            if hasattr(self.llm, "model")
                            else "mock_llm"
                        ),
                        prompt_for_log,
                        response,
                        json.dumps([v["violation"] for v in ethical_violations]),
                        json.dumps(cultural_profile),
                    ),
                )
                conn.commit()
        except Exception as e:
            logging.error(f"Database Error: Failed to log LLM interaction: {e}")
        finally:
            if conn:
                conn.close()

    def _generate_rule_based_recommendation(
        self, history: List[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Provides a basic, non-LLM recommendation."""
        if not history:
            return {
                "tactic": "Opening Move",
                "reason": "Establish a positive and open start.",
                "bot_response": "Thank you for joining. I'm looking forward to our discussion.",
            }
        last_analysis = history[-1].get("analysis", {})
        if last_analysis.get("sentiment") == "negative":
            return {
                "tactic": "De-escalate",
                "reason": "The sentiment of the last message was negative.",
                "bot_response": "I sense some concern. Can we revisit that last point to make sure we're aligned?",
            }
        return {
            "tactic": "Collaborative Exploration",
            "reason": "The negotiation is stable. Time to explore options.",
            "bot_response": "That's an interesting point. How can we build on that idea together?",
        }


# --- CLI Command for Simulation ---


@negotiation_app.command("simulate")
def run_simulation(
    use_llm: bool = typer.Option(
        False, "--llm", help="Enable the Gemini LLM for generating responses."
    ),
    use_mock_llm: bool = typer.Option(
        False, "--mock", help="Use a mock LLM for testing (avoids API calls)."
    ),
    country_code: str = typer.Option(
        "US", "--country", help="Set the counterparty's country code (e.g., JP, DE)."
    ),
):
    """Starts an interactive negotiation simulation."""
    console.print(
        f"[bold yellow]--- Starting Negotiation Simulation (LLM Enabled: {use_llm}) ---[/bold yellow]"
    )

    # Initialize the engine with database parameters from API_KEYS

    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }

    engine = NegotiationEngine(
        db_params=db_params, use_llm=use_llm, use_mock_llm=use_mock_llm
    )
    history = []

    # Initial AI message to kick off the conversation

    recommendation = engine.recommend_tactic(history, country_code)
    console.print(f"\\n[bold green]AI:[/bold green] {recommendation['bot_response']}")
    history.append(
        {"sender": "ai", "content": recommendation["bot_response"], "analysis": {}}
    )

    # Main simulation loop

    while True:
        user_input = console.input("\\n[bold blue]You:[/bold blue] ")
        if user_input.lower() in ["exit", "quit"]:
            console.print("[bold yellow]--- Simulation Ended ---[/bold yellow]")
            break
        analysis = engine.analyze_message(user_input)
        history.append({"sender": "user", "content": user_input, "analysis": analysis})

        recommendation = engine.recommend_tactic(history, country_code)
        console.print(
            f"\\n[bold green]AI:[/bold green] {recommendation['bot_response']}"
        )
        history.append(
            {"sender": "ai", "content": recommendation["bot_response"], "analysis": {}}
        )


if __name__ == "__main__":
    negotiation_app()
