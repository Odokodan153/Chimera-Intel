# src/chimera_intel/core/advanced_reasoning_engine.py


import logging
import json
import re
from typing import List, Dict, Any

from .gemini_client import call_gemini_api
from .schemas import AnalysisResult, ReasoningOutput

logger = logging.getLogger(__name__)


def decompose_objective_llm(objective: str) -> List[Dict[str, Any]]:
    """
    Uses the Gemini LLM to decompose a high-level objective into initial, actionable tasks.
    """
    prompt = f"""
You are a mission planner for a cyber intelligence AI framework.
Your task is to decompose a high-level objective into a series of initial, concrete tasks for different modules.

Objective: "{objective}"

Instructions:
1.  Identify key actionable entities in the objective (e.g., domain names, IP addresses, company names, individuals).
2.  For each entity, suggest an initial module to run. Available modules are: 'footprint', 'threat_intel', 'vulnerability_scanner'.
3.  Format the output as a JSON list of objects, where each object has 'module' and 'params' keys.
    - For 'footprint', the parameter is 'domain'.
    - For 'threat_intel', the parameter is 'indicator'.
    - For 'vulnerability_scanner', the parameter is 'host'.

Example for "Investigate the security posture of example.com":
[
    {{"module": "footprint", "params": {{"domain": "example.com"}}}}
]
"""
    llm_response = call_gemini_api(prompt)
    if not llm_response:
        logger.error("LLM call for objective decomposition returned an empty response.")
        # Minimal safe fallback: notify the user and provide a simple task
        # A dynamic fallback could attempt to parse the objective with regex

        domain_match = re.search(r"([a-zA-Z0-9.-]+\.[a-z]{2,})", objective)
        if domain_match:
            domain = domain_match.group(1)
            logger.warning(
                f"Using dynamic fallback, starting with footprint for: {domain}"
            )
            return [{"module": "footprint", "params": {"domain": domain}}]
        return []
    try:
        tasks = json.loads(llm_response)

        # Basic validation of the LLM output

        if isinstance(tasks, list) and all(
            isinstance(t, dict) and "module" in t and "params" in t for t in tasks
        ):
            logger.info(f"LLM decomposed objective into {len(tasks)} initial tasks.")
            return tasks
        else:
            raise ValueError("LLM output is not in the expected format.")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM JSON response for decomposition: {e}")
        logger.debug(
            f"Raw LLM response: {llm_response}"
        )  # Log raw output for debugging
    except (ValueError, TypeError) as e:
        logger.error(f"LLM objective decomposition failed due to invalid format: {e}.")
    return []  # Return empty list on any failure


def generate_reasoning_llm(
    objective: str, results: list[AnalysisResult]
) -> ReasoningOutput:
    """
    Uses the Gemini LLM to generate hypotheses, recommendations, and next steps
    based on completed analysis results.
    """
    output = ReasoningOutput(analytical_summary="")

    # --- Improved Serialization ---

    serialized_results = []
    for r in results:
        # Prefer Pydantic's dict() method, then check for dict/list, finally fallback to str()

        if hasattr(r.data, "dict") and callable(r.data.dict):
            data = r.data.dict()
        elif isinstance(r.data, (dict, list)):
            data = r.data
        else:
            data = str(r.data)
        serialized_results.append({"module": r.module_name, "data": data})
    prompt = f"""
You are a cyber intelligence analyst AI.
Objective: {objective}

Completed Analysis Results:
{json.dumps(serialized_results, indent=2, default=str)}

Instructions:
- Identify potential threats, patterns, and anomalies (Hypotheses)
- Recommend next investigative actions (Recommendations)
- Suggest concrete next steps/tasks for modules (Next Steps), with module name and parameters
- Provide a concise analytical summary.

Return your answer strictly in JSON with keys:
'hypotheses', 'recommendations', 'next_steps', 'analytical_summary'.
"""

    llm_response = call_gemini_api(prompt)
    if not llm_response:
        logger.error("LLM call for reasoning returned an empty response.")
        output.analytical_summary = "Reasoning failed: no response from LLM."
        return output
    try:
        response_json = json.loads(llm_response)

        output.hypotheses = response_json.get("hypotheses", [])
        output.recommendations = response_json.get("recommendations", [])
        output.next_steps = response_json.get("next_steps", [])
        output.analytical_summary = response_json.get("analytical_summary", "")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM JSON response for reasoning: {e}")
        logger.debug(
            f"Raw LLM response: {llm_response}"
        )  # Log raw output for debugging
        output.analytical_summary = "Reasoning failed due to malformed LLM response."
    # This guard prevents the reasoning engine from creating a recursive loop
    # by repeatedly calling the 'footprint' module.

    if any(r.module_name == "footprint" for r in results):
        output.next_steps = [
            step for step in output.next_steps if step.get("module") != "footprint"
        ]
    return output


# Alias the LLM-based functions to be the default


generate_reasoning = generate_reasoning_llm
decompose_objective = decompose_objective_llm
