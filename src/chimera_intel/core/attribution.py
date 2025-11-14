"""
Threat attribution and confidence scoring module.

Provides tools to assign quantifiable confidence scores to
threat actor attributions based on correlated evidence.
"""

import logging
from typing import Optional, List, Dict, Any
import json
import os
import typer
from chimera_intel.core.schemas import AttributionScoreResult
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.database import save_scan_to_db

logger = logging.getLogger(__name__)

DEFAULT_ACTOR_DB_PATH = os.path.join(os.path.dirname(__file__), "threat_actor_db.json")

def load_actor_db_from_file(db_path: str = DEFAULT_ACTOR_DB_PATH) -> Dict[str, Dict[str, Any]]:
    """
    (REAL) Loads a threat actor DB from a JSON file.
    """
    if not os.path.exists(db_path):
        logger.warning(f"Threat actor DB file not found at: {db_path}. Using empty DB.")
        # Create an empty file to prevent future errors
        try:
            with open(db_path, "w") as f:
                json.dump({}, f)
        except Exception:
            pass # Failsafe
        return {}
        
    try:
        with open(db_path, "r") as f:
            external_db = json.load(f)
        logger.info(f"Successfully loaded threat actor DB from {db_path}")
        return external_db
    except Exception as e:
        logger.error(f"Failed to load external threat actor DB from {db_path}: {e}")
        return {}
# --- (END ADDED FUNCTION) ---


def score_attribution_confidence(
    proposed_actor: str, indicators: List[Dict[str, Any]], actor_db: Dict[str, Dict[str, Any]]
) -> AttributionScoreResult:
    """
    Assigns a quantifiable confidence score to a proposed threat actor attribution.

    Args:
        proposed_actor (str): The name of the proposed threat actor (e.g., "APT-42").
        indicators (List[Dict[str, Any]]): A list of indicators observed.
            Example: [{"type": "TTP", "id": "T1059.001", "weight": 0.8},
                      {"type": "IOC", "value": "1.2.3.4", "weight": 0.5}]
        actor_db (Dict[str, Dict[str, Any]]): The threat actor knowledge base.

    Returns:
        AttributionScoreResult: A Pydantic model with the calculated score and evidence.
    """
    logger.info(f"Calculating attribution confidence for actor: {proposed_actor}")

    actor_profile = actor_db.get(proposed_actor)
    if not actor_profile:
        return AttributionScoreResult(
            proposed_actor=proposed_actor,
            confidence_score=0.0,
            total_indicators_provided=len(indicators),
            matched_indicators=[],
            conflicting_indicators=[],
            unknown_indicators=indicators,
            error=f"Threat actor '{proposed_actor}' not found in knowledge base."
        )

    actor_ttps = actor_profile.get("ttps", {})
    
    total_score = 0.0
    total_weight = 0.0
    matched = []
    conflicting = []
    unknown = []

    for ind in indicators:
        indicator_type = ind.get("type", "").lower()
        indicator_id = ind.get("id")
        user_weight = ind.get("weight", 1.0) # User's confidence in this indicator
        
        if not indicator_id:
            unknown.append(ind)
            continue
            
        if indicator_type == "ttp":
            if indicator_id in actor_ttps:
                # Matched! Score is (Actor_TTP_Weight * User_Weight)
                actor_weight = actor_ttps[indicator_id]
                score_contribution = actor_weight * user_weight
                total_score += score_contribution
                total_weight += user_weight # Use user_weight as the max possible score
                ind["match_confidence"] = actor_weight
                matched.append(ind)
            else:
                # Check if this TTP belongs to *other* actors (conflicting)
                is_conflicting = False
                for actor_name, profile in actor_db.items():
                    if actor_name != proposed_actor and indicator_id in profile.get("ttps", {}):
                        ind["conflicts_with"] = actor_name
                        conflicting.append(ind)
                        is_conflicting = True
                        break
                if not is_conflicting:
                    unknown.append(ind)
        else:
            # Logic for other indicator types (IOC, domain, etc.)
            # This can be expanded similarly to TTPs
            unknown.append(ind)
            
    # Calculate final score: (Total accumulated score / Max possible score)
    if total_weight == 0:
        final_score = 0.0
    else:
        final_score = total_score / total_weight
        
    final_score = min(max(final_score, 0.0), 1.0) # Normalize to 0.0 - 1.0

    return AttributionScoreResult(
        proposed_actor=proposed_actor,
        confidence_score=final_score,
        total_indicators_provided=len(indicators),
        matched_indicators=matched,
        conflicting_indicators=conflicting,
        unknown_indicators=unknown
    )


# --- Typer CLI Application ---

attribution_app = typer.Typer()

@attribution_app.command("score-actor")
def run_attribution_score(
    proposed_actor: str = typer.Argument(..., help="The proposed threat actor (e.g., 'APT-42')."),
    indicators_json: str = typer.Argument(..., help="JSON string of indicators. E.g., '[{{\"type\": \"TTP\", \"id\": \"T1059.001\", \"weight\": 0.7}}]'"),
    db_path: Optional[str] = typer.Option(None, help="Path to a custom threat actor JSON DB file."),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to a JSON file."),
):
    """Calculates a confidence score for a threat actor attribution."""
    
    try:
        indicators = json.loads(indicators_json)
        if not isinstance(indicators, list):
            raise ValueError("JSON input must be a list.")
    except Exception as e:
        console.print(f"[bold red]Error:[/] Invalid JSON format for indicators: {e}", style="red")
        raise typer.Exit(code=1)

    # --- (UPDATED) Load the actor database ---
    actor_db = load_actor_db_from_file(db_path) if db_path else load_actor_db_from_file()
    if not actor_db and not db_path:
        console.print(f"[yellow]Warning:[/yellow] Default threat actor DB is empty or missing ({DEFAULT_ACTOR_DB_PATH}).")
    # --- (END UPDATE) ---

    results = score_attribution_confidence(proposed_actor, indicators, actor_db)
    save_or_print_results(results.model_dump(), output_file)
    save_scan_to_db(
        target=proposed_actor, module="analysis_attribution", data=results.model_dump()
    )