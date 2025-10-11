from typing import Dict, Any

def get_personas() -> Dict[str, Dict[str, Any]]:
    """
    Returns a dictionary of predefined negotiation personas.

    These personas are used to give the AI agent a specific style and strategy
    during a negotiation simulation. Each persona has a distinct description
    and risk appetite, which can be used to influence the LLM's responses
    and the RL agent's reward structure.
    """
    return {
        "cooperative": {
            "name": "Cooperative",
            "description": (
                "Seeks win-win outcomes, values long-term relationships, "
                "and is willing to make reasonable concessions to find common ground."
            ),
            "risk_appetite": "low",
            "initial_stance": "friendly",
        },
        "aggressive": {
            "name": "Aggressive",
            "description": (
                "Focuses on maximizing personal gain, often uses pressure tactics, "
                "and is not afraid to walk away from a deal if it doesn't meet their demands."
            ),
            "risk_appetite": "high",
            "initial_stance": "assertive",
        },
        "analytical": {
            "name": "Analytical",
            "description": (
                "Relies on data, logic, and objective criteria to make decisions. "
                "Prefers a structured negotiation process and is less influenced by emotion."
            ),
            "risk_appetite": "medium",
            "initial_stance": "neutral",
        },
        "principled": {
            "name": "Principled",
            "description": (
                "Focuses on fairness and ethical principles. Will not compromise on core values, "
                "even if it means losing a deal. Seeks a solution that is fair to all parties."
            ),
            "risk_appetite": "low",
            "initial_stance": "formal",
        },
        "accommodating": {
            "name": "Accommodating",
            "description": (
                "Prioritizes the relationship over the outcome. Is quick to make concessions "
                "and wants to ensure the other party is happy with the result."
            ),
            "risk_appetite": "low",
            "initial_stance": "warm",
        },
    }

def get_persona(name: str) -> Dict[str, Any]:
    """
    Retrieves a specific persona by name.

    Args:
        name: The name of the persona to retrieve.

    Returns:
        A dictionary containing the persona's attributes, or a default
        "neutral" persona if the requested one is not found.
    """
    personas = get_personas()
    return personas.get(name.lower(), {
        "name": "Neutral",
        "description": "A balanced negotiator with no strong predispositions.",
        "risk_appetite": "medium",
        "initial_stance": "neutral",
    })