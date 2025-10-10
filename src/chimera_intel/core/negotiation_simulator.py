from typing import Dict, Any
from .negotiation import NegotiationEngine


class AIPersona:
    """Defines the behavior and strategy of an AI negotiation persona."""

    def __init__(
        self,
        name: str,
        description: str,
        engine: NegotiationEngine,
        response_rules: Dict[str, str],
    ):
        self.name = name
        self.description = description
        self.engine = engine
        self.rules = response_rules

    def generate_response(self, user_message: str, history: list) -> Dict[str, Any]:
        """
        Analyzes a user's message and generates a response based on the persona's rules.
        """
        analysis = self.engine.analyze_message(user_message)
        tactic_recommendation = self.engine.recommend_tactic(history)

        # Apply persona-specific logic

        base_response = tactic_recommendation.get(
            "bot_response", "I'm not sure how to respond to that."
        )
        final_response_text = self.rules.get(analysis["intent"], base_response)

        # Simulate persona-specific offer logic

        if analysis["intent"] == "offer" and analysis["offer_amount"]:
            if self.name == "Aggressive Andy":
                # Always counter slightly higher

                offer_response = analysis["offer_amount"] * 1.15
                final_response_text = f"That's a start, but I was thinking more in the range of ${offer_response:,.2f}."
            elif self.name == "Cooperative Clara":
                # Meet in the middle

                offer_response = analysis["offer_amount"] * 0.95
                final_response_text = f"I appreciate that offer. What if we settled around ${offer_response:,.2f}?"
        return {
            "persona_response": final_response_text,
            "tactic": tactic_recommendation.get("tactic"),
            "analysis": analysis,
        }


def get_personas() -> Dict[str, AIPersona]:
    """
    Initializes and returns a dictionary of all available AI personas.
    """
    engine = NegotiationEngine()  # Using the base engine for all personas

    personas = {
        "cooperative": AIPersona(
            name="Cooperative Clara",
            description="Focuses on win-win outcomes and maintaining positive relationships.",
            engine=engine,
            response_rules={
                "rejection": "I understand your position. Let's work together to find a solution that suits us both.",
                "condition": "That's a fair condition. Let me see how we can meet that.",
            },
        ),
        "aggressive": AIPersona(
            name="Aggressive Andy",
            description="Drives a hard bargain and focuses on maximizing their own gains.",
            engine=engine,
            response_rules={
                "offer": "We can do better than that.",
                "acceptance": "Good. Let's get this signed.",
            },
        ),
        "analytical": AIPersona(
            name="Analytical Anna",
            description="Relies on data and logic, avoiding emotional arguments.",
            engine=engine,
            response_rules={
                "discussion": "Let's review the data. The numbers indicate that...",
                "offer": "Your offer is outside the expected range based on my model. Can you justify that figure?",
            },
        ),
    }
    return personas
