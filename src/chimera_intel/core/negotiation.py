import psycopg2
import json
import typer
from rich.console import Console
from typing import List, Dict, Any, Optional, Union
from textblob import TextBlob
import logging
from enum import Enum
import asyncio
import uuid

# --- Imports for LLM Integration ---


from .llm_interface import LLMInterface, MockLLMInterface
from .negotiation_rl_agent import QLearningLLMAgent, QLearningAgent
from .ethical_guardrails import EthicalFramework
from .cultural_intelligence import get_cultural_profile
from .advanced_nlp import AdvancedNLPAnalyzer
from .config_loader import API_KEYS
from .analytics import plot_sentiment_trajectory
from .schemas import NegotiationSession, Message, ChannelType
from .database import get_db_connection
from .schemas import NegotiationParticipant, SimulationMode


# --- CLI Application Definition ---


console = Console()
negotiation_app = typer.Typer(
    help="A comprehensive suite for AI-assisted negotiation, analysis, and training."
)

logger = logging.getLogger(__name__)

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
        mode: SimulationMode = SimulationMode.inference,
    ):
        """
        Initializes the engine and its components.
        """
        self.positive_sentiment_threshold = positive_sentiment_threshold
        self.negative_sentiment_threshold = negative_sentiment_threshold
        self.db_params = db_params
        self.ethical_framework = EthicalFramework()
        self.advanced_nlp_analyzer = AdvancedNLPAnalyzer()
        self.llm: Optional[Union[LLMInterface, MockLLMInterface]] = None
        self.mode = mode
        self.rl_agent: Union[QLearningLLMAgent, QLearningAgent]

        use_mock_llm = self.mode == SimulationMode.training

        if use_llm:
            try:
                if use_mock_llm:
                    self.llm = MockLLMInterface()
                    logger.info("Using Mock LLM Interface for training.")
                else:
                    self.llm = LLMInterface()
                    logger.info("Using live Gemini LLM Interface for inference.")
                if self.llm:
                    self.rl_agent = QLearningLLMAgent(
                        llm=self.llm,
                        ethics=self.ethical_framework,
                        db_params=self.db_params,
                        action_space_n=3,
                    )
                    logger.info("Initialized with QLearningLLMAgent.")
                else:
                    self.rl_agent = QLearningAgent(action_space_n=3)
            except ValueError as e:
                logger.error(
                    f"LLM Initialization Failed: {e}. Falling back to standard agent."
                )
                self.rl_agent = QLearningAgent(action_space_n=3)
        else:
            self.rl_agent = QLearningAgent(action_space_n=3)
            logger.info("Initialized with standard QLearningAgent.")
        if rl_model_path:
            try:
                if isinstance(self.rl_agent, QLearningAgent):
                    self.rl_agent.load_model(rl_model_path)
                    self.rl_agent.epsilon = 0.1
                logger.info(f"Successfully loaded RL model from {rl_model_path}")
            except FileNotFoundError:
                logger.warning(
                    f"RL model not found at {rl_model_path}. Using a new, untrained agent."
                )

    def _get_db_connection(self):
        """Establishes a connection to the database."""
        if not self.db_params:
            logger.warning("Database parameters are not configured.")
            return None
        try:
            return psycopg2.connect(**self.db_params)
        except psycopg2.OperationalError as e:
            logger.error(f"Database Connection Error: {e}")
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

    async def recommend_tactic_async(
        self,
        history: List[Dict[str, Any]],
        counterparty_country_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Selects a tactic and generates a response asynchronously, using the LLM if available.
        """
        state_representation = self._get_state_from_history(history)
        action = self.rl_agent.choose_action(state_representation)
        reward = self.get_reward(state_representation, history)

        self._log_rl_step(state_representation, action, reward)

        if isinstance(self.rl_agent, QLearningLLMAgent):
            bot_response = self.rl_agent.generate_negotiation_message(
                state_representation, counterparty_country_code
            )
            self._log_llm_interaction(
                state_representation,
                action,
                reward,
                bot_response,
                counterparty_country_code,
            )
            return {
                "tactic": "LLM-Generated Response",
                "reason": "Dynamically generated by the language model based on the negotiation context.",
                "bot_response": bot_response,
            }
        return self._generate_rule_based_recommendation(history)

    def get_reward(self, state: Dict[str, Any], history: List[Dict[str, Any]]) -> float:
        """
        Calculates a more sophisticated reward based on the current state and history.
        """
        reward: float = 0.0
        # Sentiment-based reward

        if state.get("last_message_sentiment") == "positive":
            reward += 0.2
        elif state.get("last_message_sentiment") == "negative":
            reward -= 0.2
        # Reward for making progress

        if "offer" in state.get("last_message_content", "").lower():
            reward += 0.3
        if "accept" in state.get("last_message_content", "").lower():
            reward += 1.0  # Strong reward for reaching an agreement
        if "reject" in state.get("last_message_content", "").lower():
            reward -= 0.5  # Penalty for rejection
        # Reward for concessions (a simple heuristic)

        if len(history) > 1:
            last_message = history[-1]
            if "offer" in last_message.get("content", "").lower():
                # A more complex implementation would parse the offer amounts

                reward += 0.1  # Small reward for making a concession
        return reward

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

    def _log_rl_step(self, state: Dict[str, Any], action: int, reward: float):
        """Logs the state, action, and reward for RL analytics."""
        conn = self._get_db_connection()
        if not conn:
            return
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO rl_logs (state, action, reward)
                    VALUES (%s, %s, %s);
                """,
                    (json.dumps(state), action, reward),
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Database Error: Failed to log RL step: {e}")
        finally:
            if conn:
                conn.close()

    def _log_llm_interaction(
        self,
        state: Dict[str, Any],
        action: int,
        reward: float,
        response: str,
        country_code: Optional[str],
    ):
        """Logs the LLM interaction details to the database."""
        conn = self._get_db_connection()
        if not conn or not isinstance(self.rl_agent, QLearningLLMAgent) or not self.llm:
            return
        cultural_profile = get_cultural_profile(country_code) if country_code else {}
        ethical_violations = self.ethical_framework.check_message(response)

        prompt_for_log = f"State: {json.dumps(state)}, Cultural Profile: {json.dumps(cultural_profile)}"

        try:
            with conn.cursor() as cursor:
                model_name = "mock_llm"
                if hasattr(self.llm, "model") and hasattr(self.llm.model, "model_name"):
                    model_name = self.llm.model.model_name
                cursor.execute(
                    """
                    INSERT INTO llm_logs (model_name, prompt, response, ethical_flags, cultural_context, state, action, reward)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """,
                    (
                        model_name,
                        prompt_for_log,
                        response,
                        json.dumps([v["violation"] for v in ethical_violations]),
                        json.dumps(cultural_profile),
                        json.dumps(state),
                        action,
                        reward,
                    ),
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Database Error: Failed to log LLM interaction: {e}")
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

    def simulate_outcome(self, simulation_scenario: Dict[str, int]) -> Dict[str, Any]:
        """
        Simulates a negotiation outcome based on a simple scenario.
        """
        our_min = simulation_scenario.get("our_min", 5000)
        our_max = simulation_scenario.get("our_max", 10000)
        their_min = simulation_scenario.get("their_min", 7000)
        their_max = simulation_scenario.get("their_max", 12000)

        overlap_min = max(our_min, their_min)
        overlap_max = min(our_max, their_max)

        if overlap_min > overlap_max:
            return {
                "outcome": "No Deal Likely",
                "reason": "There is no overlapping range between the two parties.",
                "settlement_point": None,
            }
        settlement_point = (overlap_min + overlap_max) / 2
        return {
            "outcome": "Deal is Possible",
            "reason": f"An overlapping negotiation range exists between {overlap_min} and {overlap_max}.",
            "settlement_point": settlement_point,
        }


# --- CLI Commands ---


@negotiation_app.command("simulate")
def run_simulation(
    use_llm: bool = typer.Option(
        False, "--llm", help="Enable the Gemini LLM for generating responses."
    ),
    mode: SimulationMode = typer.Option(
        SimulationMode.inference,
        "--mode",
        help="Set the simulation mode to 'training' or 'inference'.",
    ),
    country_code: str = typer.Option(
        "US", "--country", help="Set the counterparty's country code (e.g., JP, DE)."
    ),
    deterministic_opponent: bool = typer.Option(
        False,
        "--deterministic",
        help="Use a deterministic opponent for reproducible training.",
    ),
):
    """Starts an interactive negotiation simulation."""
    console.print(
        f"[bold yellow]--- Starting Negotiation Simulation (Mode: {mode.value}, LLM Enabled: {use_llm}) ---[/bold yellow]"
    )

    db_params = {
        "dbname": getattr(API_KEYS, "db_name", None),
        "user": getattr(API_KEYS, "db_user", None),
        "password": getattr(API_KEYS, "db_password", None),
        "host": getattr(API_KEYS, "db_host", None),
    }

    engine = NegotiationEngine(db_params=db_params, use_llm=use_llm, mode=mode)
    history: List[Dict[str, Any]] = []

    recommendation = asyncio.run(engine.recommend_tactic_async(history, country_code))
    console.print(f"\n[bold green]AI:[/bold green] {recommendation['bot_response']}")
    history.append(
        {"sender": "ai", "content": recommendation["bot_response"], "analysis": {}}
    )

    while True:
        if deterministic_opponent:
            if len(history) % 4 == 1:
                user_input = "I can offer a 10% reduction."
            elif len(history) % 4 == 3:
                user_input = "That's not good enough."
            else:
                user_input = "What else can you do for me?"
            console.print(
                f"\n[bold blue]Deterministic Opponent:[/bold blue] {user_input}"
            )
        else:
            user_input = console.input("\n[bold blue]You:[/bold blue] ")
        if user_input.lower() in ["exit", "quit"]:
            console.print("[bold yellow]--- Simulation Ended ---[/bold yellow]")
            plot_sentiment_trajectory("")
            break
        analysis = engine.analyze_message(user_input)
        history.append({"sender": "user", "content": user_input, "analysis": analysis})

        recommendation = asyncio.run(
            engine.recommend_tactic_async(history, country_code)
        )
        console.print(
            f"\n[bold green]AI:[/bold green] {recommendation['bot_response']}"
        )
        history.append(
            {"sender": "ai", "content": recommendation["bot_response"], "analysis": {}}
        )


@negotiation_app.command("start")
def start_negotiation(
    subject: str = typer.Argument(..., help="The subject of the negotiation.")
):
    """
    Starts a new negotiation session.
    """
    db = next(get_db_connection())
    session_id = str(uuid.uuid4())
    db_negotiation = NegotiationSession(id=session_id, subject=subject)
    db.add(db_negotiation)
    db.commit()
    db.refresh(db_negotiation)
    console.print(
        f"Negotiation session started with ID: [bold yellow]{session_id}[/bold yellow]"
    )


@negotiation_app.command("join")
def join_negotiation(
    session_id: str = typer.Argument(..., help="The ID of the negotiation session."),
    user_id: str = typer.Argument(..., help="The ID of the user joining the session."),
):
    """
    Adds a user to an existing negotiation session.
    """
    db = next(get_db_connection())
    session = (
        db.query(NegotiationSession)
        .filter(NegotiationSession.id == session_id)
        .first()
    )
    if not session:
        console.print(f"Negotiation session with ID {session_id} not found.")
        return
    # Assuming a simple user model for now

    participant = NegotiationParticipant(
        session_id=session_id, participant_id=user_id, participant_name=user_id
    )
    db.add(participant)
    db.commit()
    console.print(f"User {user_id} has joined negotiation {session_id}.")


@negotiation_app.command("leave")
def leave_negotiation(
    session_id: str = typer.Argument(..., help="The ID of the negotiation session."),
    user_id: str = typer.Argument(..., help="The ID of the user leaving the session."),
):
    """
    Removes a user from a negotiation session.
    """
    db = next(get_db_connection())
    participant = (
        db.query(NegotiationParticipant)
        .filter(
            NegotiationParticipant.session_id == session_id,
            NegotiationParticipant.participant_id == user_id,
        )
        .first()
    )
    if not participant:
        console.print(f"User {user_id} not found in negotiation {session_id}.")
        return
    db.delete(participant)
    db.commit()
    console.print(f"User {user_id} has left negotiation {session_id}.")


@negotiation_app.command("offer")
def make_offer(
    session_id: str = typer.Argument(..., help="The ID of the negotiation session."),
    user_id: str = typer.Argument(..., help="The ID of the user making the offer."),
    offer: str = typer.Argument(..., help="The offer being made."),
):
    """
    Makes an offer in a negotiation.
    """
    db = next(get_db_connection())
    message = Message(
        id=str(uuid.uuid4()),
        negotiation_id=session_id,
        sender_id=user_id,
        content=f"Offer: {offer}",
        analysis={},
        channel=ChannelType.CHAT,
    )
    db.add(message)
    db.commit()
    console.print(f"Offer from {user_id} in session {session_id} recorded.")


@negotiation_app.command("accept")
def accept_offer(
    session_id: str = typer.Argument(..., help="The ID of the negotiation session."),
    user_id: str = typer.Argument(..., help="The ID of the user accepting the offer."),
):
    """
    Accepts an offer in a negotiation.
    """
    db = next(get_db_connection())
    message = Message(
        id=str(uuid.uuid4()),
        negotiation_id=session_id,
        sender_id=user_id,
        content="Offer accepted.",
        analysis={},
        channel=ChannelType.CHAT,
    )
    db.add(message)
    db.commit()
    console.print(f"Acceptance from {user_id} in session {session_id} recorded.")


@negotiation_app.command("reject")
def reject_offer(
    session_id: str = typer.Argument(..., help="The ID of the negotiation session."),
    user_id: str = typer.Argument(..., help="The ID of the user rejecting the offer."),
):
    """
    Rejects an offer in a negotiation.
    """
    db = next(get_db_connection())
    message = Message(
        id=str(uuid.uuid4()),
        negotiation_id=session_id,
        sender_id=user_id,
        content="Offer rejected.",
        analysis={},
        channel=ChannelType.CHAT,
    )
    db.add(message)
    db.commit()
    console.print(f"Rejection from {user_id} in session {session_id} recorded.")


@negotiation_app.command("history")
def get_history(
    session_id: str = typer.Argument(..., help="The ID of the negotiation session.")
):
    """
    Gets the history of a negotiation session.
    """
    db = next(get_db_connection())
    session = (
        db.query(NegotiationSession)
        .filter(NegotiationSession.id == session_id)
        .first()
    )
    if not session:
        console.print(f"Negotiation session with ID {session_id} not found.")
        return
    for message in session.messages:
        console.print(f"  [{message.sender_id}] {message.content}")


@negotiation_app.command("status")
def negotiation_status(
    session_id: str = typer.Argument(..., help="The ID of the negotiation session.")
):
    """
    Gets the status of a negotiation session.
    """
    db = next(get_db_connection())
    session = (
        db.query(NegotiationSession)
        .filter(NegotiationSession.id == session_id)
        .first()
    )
    if not session:
        console.print(f"Negotiation session with ID {session_id} not found.")
        return
    console.print(f"Subject: {session.subject}")
    console.print(f"Started at: {session.start_time}")
    for message in session.messages:
        console.print(f"  [{message.sender_id}] {message.content}")


if __name__ == "__main__":
    negotiation_app()