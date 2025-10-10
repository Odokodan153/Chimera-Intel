from typing import Dict, Any, List
from textblob import TextBlob


def analyze_communication_style(text: str) -> str:
    """Analyzes text to determine communication style (formal vs. informal)."""
    # Simple heuristic: longer sentences and more complex words suggest formality.

    blob = TextBlob(text)
    avg_sentence_length = sum(len(s.words) for s in blob.sentences) / len(
        blob.sentences
    )

    if avg_sentence_length > 20:
        return "Formal"
    else:
        return "Informal"


def analyze_risk_appetite(text: str) -> str:
    """Analyzes text to determine risk appetite."""
    # Simple heuristic: words related to certainty vs. possibility.

    risk_seeking_words = ["opportunity", "growth", "potential", "upside"]
    risk_averse_words = ["guarantee", "secure", "risk", "threat", "protect"]

    seeking_score = sum(1 for word in risk_seeking_words if word in text.lower())
    averse_score = sum(1 for word in risk_averse_words if word in text.lower())

    if seeking_score > averse_score:
        return "Risk-seeking"
    else:
        return "Risk-averse"


def generate_behavioral_profile(text_samples: List[str]) -> Dict[str, Any]:
    """Generates a behavioral profile from a list of text samples."""
    full_text = " ".join(text_samples)

    communication_style = analyze_communication_style(full_text)
    risk_appetite = analyze_risk_appetite(full_text)

    return {
        "communication_style": communication_style,
        "risk_appetite": risk_appetite,
    }
