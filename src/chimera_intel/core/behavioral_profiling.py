import logging
import json
import re
from typing import Dict, Any, List
from textblob import TextBlob  # Import TextBlob for rule-based analysis
from .ai_core import generate_swot_from_data  # Re-using for general AI generation
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)

# --- 1. AI-Powered Implementation (Primary) ---

async def _generate_behavioral_profile_ai(text_samples: List[str], api_key: str) -> Dict[str, Any]:
    """
    (REAL) Generates a behavioral profile from a list of text samples
    using a generative AI model.
    """
    full_text = " ".join(text_samples)
    
    # Truncate to avoid excessive prompt size
    if len(full_text) > 8000:
        full_text = full_text[:8000]

    prompt = f"""
    As an intelligence psychologist, analyze the following text samples from a target individual.
    Based on the language, tone, and recurring themes, generate a behavioral profile.

    **Source Text:**
    "{full_text}"

    **Instructions:**
    Return your analysis as a single, valid JSON object with the following keys:
    1.  "communication_style": (string) A concise description (e.g., "Formal and data-driven", "Informal and persuasive", "Cautious and non-committal").
    2.  "risk_appetite": (string) The perceived risk appetite (e.g., "Risk-averse", "Risk-neutral", "Risk-seeking").
    3.  "key_motivators": (list of strings) A list of inferred key motivators (e.g., "Financial gain", "Public recognition", "Maintaining stability", "Innovation").
    4.  "executive_summary": (string) A 2-3 sentence summary of the overall profile.
    5.  "analysis_backend": "gemini_ai"

    Return ONLY the valid JSON object and no other text.
    """

    try:
        # Re-using the generic text generation function from ai_core
        ai_result = generate_swot_from_data(prompt, api_key)
        
        if ai_result.error:
            raise Exception(ai_result.error)
            
        # Clean and parse the JSON response
        json_text = ai_result.analysis_text.strip().lstrip("```json").rstrip("```")
        profile_data = json.loads(json_text)
        
        return profile_data

    except Exception as e:
        logger.error(f"Failed to generate AI behavioral profile: {e}", exc_info=True)
        return {"error": f"AI analysis failed: {e}"}


# --- 2. Rule-Based Implementation (Fallback) ---

def _analyze_communication_style_rules(blob: TextBlob) -> str:
    """Analyzes text to determine communication style (formal vs. informal)."""
    
    if not blob.sentences:
        return "Unknown (No text)"

    avg_sentence_length = sum(len(s.words) for s in blob.sentences) / len(blob.sentences)
    
    # Count complex words (e.g., > 3 syllables) - simple heuristic
    complex_words = sum(1 for word in blob.words if len(word) > 10)
    complexity_ratio = complex_words / len(blob.words) if blob.words else 0
    
    # Heuristics for formality
    formality_score = 0
    if avg_sentence_length > 20:
        formality_score += 1
    if complexity_ratio > 0.1:
        formality_score += 1
    if blob.sentiment.subjectivity < 0.3:
        formality_score += 1 # Objective tone often correlates with formality

    if formality_score >= 2:
        return f"Formal and objective (Avg. sentence: {avg_sentence_length:.1f} words, Subjectivity: {blob.sentiment.subjectivity:.2f})"
    elif formality_score == 1:
        return f"Neutral (Mixed formality)"
    else:
        return f"Informal and subjective (Avg. sentence: {avg_sentence_length:.1f} words, Subjectivity: {blob.sentiment.subjectivity:.2f})"


def _analyze_risk_appetite_rules(text_lower: str) -> str:
    """Analyzes text to determine risk appetite."""
    risk_seeking_words = [
        "opportunity", "growth", "potential", "upside", "innovate",
        "disrupt", "pioneer", "new market", "aggressive"
    ]
    risk_averse_words = [
        "guarantee", "secure", "risk", "threat", "protect", "stability",
        "cautious", "reliable", "proven", "mitigate", "compliance"
    ]

    seeking_score = sum(text_lower.count(word) for word in risk_seeking_words)
    averse_score = sum(text_lower.count(word) for word in risk_averse_words)

    if (seeking_score - averse_score) > 3:
        return "Risk-seeking"
    elif (averse_score - seeking_score) > 3:
        return "Risk-averse"
    else:
        return "Risk-neutral"

def _analyze_key_motivators_rules(text_lower: str) -> List[str]:
    """Analyzes text for key motivator keywords."""
    motivators = {
        "Financial Gain": ["profit", "revenue", "bonus", "financial", "market share", "cost"],
        "Innovation": ["innovate", "technology", "future", "R&D", "cutting-edge"],
        "Recognition": ["leader", "best", "award", "recognition", "reputation"],
        "Stability": ["stable", "secure", "long-term", "reliable", "protect"]
    }
    
    found_motivators = []
    for motivator, keywords in motivators.items():
        if any(word in text_lower for word in keywords):
            found_motivators.append(motivator)
            
    return found_motivators or ["Not clearly defined"]


def _generate_behavioral_profile_rules(text_samples: List[str]) -> Dict[str, Any]:
    """
    (REAL) Generates a behavioral profile from a list of text samples
    using rule-based heuristics.
    """
    logger.info("Falling back to rule-based behavioral profiling.")
    
    full_text = " ".join(text_samples)
    if not full_text:
        return {"error": "No text samples provided."}

    full_text_lower = full_text.lower()
    blob = TextBlob(full_text)
    
    style = _analyze_communication_style_rules(blob)
    risk = _analyze_risk_appetite_rules(full_text_lower)
    motivators = _analyze_key_motivators_rules(full_text_lower)

    summary = (
        f"Rule-based analysis suggests a {risk} target "
        f"with a {style.split('(')[0].strip()} communication style. "
        f"Key motivators appear to include: {', '.join(motivators)}."
    )
    
    return {
        "communication_style": style,
        "risk_appetite": risk,
        "key_motivators": motivators,
        "executive_summary": summary,
        "analysis_backend": "rule_based_fallback"
    }


# --- 3. Main Router Function ---

async def generate_behavioral_profile(text_samples: List[str]) -> Dict[str, Any]:
    """
    Generates a behavioral profile from a list of text samples.
    
    Attempts to use the AI model first, and falls back to
    rule-based analysis if no API key is configured.
    """
    api_key = API_KEYS.google_api_key
    
    if api_key:
        # Use the primary AI-based implementation
        return await _generate_behavioral_profile_ai(text_samples, api_key)
    else:
        # Use the fallback rule-based implementation
        logger.warning("GOOGLE_API_KEY not found. Falling back to rule-based behavioral profiling.")
        return _generate_behavioral_profile_rules(text_samples)