from typing import Dict, Any, List
from .negotiation import NegotiationEngine
import logging

# Configure structured logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class AIPersona:
    """Defines the behavior and strategy of an AI negotiation persona."""

    def __init__(
        self,
        name: str,
        description: str,
        persona_type: str,  # e.g., "cooperative", "aggressive"
        engine: NegotiationEngine,
        response_rules: Dict[str, str],
    ):
        self.name = name
        self.description = description
        self.persona_type = persona_type
        self.engine = engine
        self.rules = response_rules

    def generate_response(
        self, user_message: str, history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyzes a user's message and generates a response based on the persona's rules.
        """
        analysis = self.engine.analyze_message(user_message)
        # Pass the full history for a more context-aware recommendation

        tactic_recommendation = self.engine.recommend_tactic(history)

        # Start with the engine's base recommendation

        final_response_text = tactic_recommendation.get(
            "bot_response", "I'm not sure how to respond to that."
        )

        # Apply persona-specific rule-based overrides

        if analysis["intent"] in self.rules:
            final_response_text = self.rules[analysis["intent"]]
        # Apply persona-specific offer logic without overwriting previous logic

        if analysis["intent"] == "offer" and analysis.get("offer_amount"):
            final_response_text = self._handle_offer(
                analysis["offer_amount"], final_response_text
            )
        return {
            "persona_response": final_response_text,
            "tactic": tactic_recommendation.get("tactic"),
            "analysis": analysis,
        }

    def _handle_offer(self, offer_amount: float, base_response: str) -> str:
        """Applies persona-specific logic to an offer."""
        offer_handlers = {
            "aggressive": lambda amount: f"That's a start, but I was thinking more in the range of ${amount * 1.15:,.2f}.",
            "cooperative": lambda amount: f"I appreciate that offer. What if we settled around ${amount * 0.95:,.2f}?",
            "analytical": lambda amount: f"Your offer of ${amount:,.2f} is outside the expected range based on my model. Can you justify that figure?",
        }
        handler = offer_handlers.get(self.persona_type)
        return handler(offer_amount) if handler else base_response


def get_personas() -> Dict[str, AIPersona]:
    """
    Initializes and returns a dictionary of all available AI personas.
    """
    engine = NegotiationEngine()  # A single engine instance can be shared

    personas = {
        "cooperative": AIPersona(
            name="Cooperative Clara",
            description="Focuses on win-win outcomes and maintaining positive relationships.",
            persona_type="cooperative",
            engine=engine,
            response_rules={
                "rejection": "I understand your position. Let's work together to find a solution that suits us both.",
                "condition": "That's a fair condition. Let me see how we can meet that.",
            },
        ),
        "aggressive": AIPersona(
            name="Aggressive Andy",
            description="Drives a hard bargain and focuses on maximizing their own gains.",
            persona_type="aggressive",
            engine=engine,
            response_rules={
                "offer": "We can do better than that.",
                "acceptance": "Good. Let's get this signed.",
            },
        ),
        "analytical": AIPersona(
            name="Analytical Anna",
            description="Relies on data and logic, avoiding emotional arguments.",
            persona_type="analytical",
            engine=engine,
            response_rules={
                "discussion": "Let's review the data. The numbers indicate that...",
            },
        ),
    }
    return personas
