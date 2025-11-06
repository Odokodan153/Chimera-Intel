import logging
import json
from typing import Dict, Any, List
from .config_loader import API_KEYS
from .ai_core import generate_swot_from_data  # Re-using for general AI generation

logger = logging.getLogger(__name__)

# --- 1. Rule-Based Fallback Logic ---

# A static, hardcoded dictionary of keywords for the fallback
_RULE_BASED_TACTICS = {
    "appeal_to_authority": {
        "description": "Citing an authority figure or expert to support a claim.",
        "keywords": [
            "experts say",
            "studies show",
            "the industry standard is",
            "proven by",
        ],
    },
    "social_proof": {
        "description": "Referencing the popularity of an idea as evidence of its validity.",
        "keywords": [
            "everyone is doing it",
            "most companies",
            "the consensus is",
            "popular choice",
        ],
    },
    "scarcity": {
        "description": "Creating a sense of urgency by highlighting limited availability.",
        "keywords": [
            "limited time offer",
            "once it's gone",
            "few left",
            "exclusive deal",
        ],
    },
}

def _detect_argument_tactics_rules(message_content: str) -> List[Dict[str, Any]]:
    """(FALLBACK) Analyzes a message for tactics using keyword matching."""
    logger.info("Falling back to rule-based tactic detection.")
    detected = []
    message_lower = message_content.lower()
    for tactic_name, tactic_data in _RULE_BASED_TACTICS.items():
        for keyword in tactic_data["keywords"]:
            if keyword in message_lower:
                detected.append(
                    {
                        "tactic": tactic_name,
                        "description": tactic_data["description"],
                        "triggered_by": keyword,
                        "analysis_backend": "rule_based_fallback"
                    }
                )
    return detected

# --- 2. AI-Powered Implementation (Primary) ---

def _detect_argument_tactics_ai(message_content: str, api_key: str) -> List[Dict[str, Any]]:
    """(REAL) Analyzes a message for tactics using a generative AI model."""
    logger.info("Using AI-based tactic detection.")
    
    prompt = f"""
    As an expert in rhetoric and logical fallacies, analyze the following message.
    Identify any argumentation tactics, persuasive techniques, or logical fallacies being used.

    Message:
    "{message_content}"

    **Instructions:**
    Return your analysis as a single, valid JSON object with a key "tactics".
    "tactics" should be a list of objects, where each object has:
    - "tactic": (string) The name of the tactic (e.g., "Appeal to Authority", "Straw Man", "Scarcity").
    - "description": (string) A brief description of how the tactic is being used here.
    - "triggered_by": (string) The specific quote or phrase from the message that triggered this detection.
    - "analysis_backend": "gemini_ai"

    If no tactics are found, return an empty list: {{"tactics": []}}
    
    Return ONLY the valid JSON object.
    """
    
    try:
        # Re-using the generic text generation function from ai_core
        ai_result = generate_swot_from_data(prompt, api_key)
        
        if ai_result.error:
            raise Exception(ai_result.error)
        
        json_text = ai_result.analysis_text.strip().lstrip("```json").rstrip("```")
        parsed_data = json.loads(json_text)
        return parsed_data.get("tactics", [])
        
    except Exception as e:
        logger.error(f"Failed to run AI tactic detection: {e}")
        logger.debug(f"Raw AI response was: {ai_result.analysis_text if 'ai_result' in locals() else 'N/A'}")
        # On AI failure, degrade gracefully to rules
        return _detect_argument_tactics_rules(message_content)

# --- 3. Main Class & Router Function ---

class AdvancedNLPAnalyzer:
    """
    Performs advanced NLP tasks to detect nuanced conversational features
    beyond basic sentiment and intent.
    """

    def __init__(self):
        """
        Initializes the analyzer.
        """
        self.api_key = API_KEYS.google_api_key

    def detect_argument_tactics(self, message_content: str) -> List[Dict[str, Any]]:
        """
        Analyzes a message to detect the presence of specific argumentation tactics.
        Uses AI if available, otherwise falls back to rules.
        """
        if self.api_key:
            return _detect_argument_tactics_ai(message_content, self.api_key)
        else:
            return _detect_argument_tactics_rules(message_content)