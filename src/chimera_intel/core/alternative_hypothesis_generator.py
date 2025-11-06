"""
Module for Alternative Hypothesis Generation.

A mandatory analytical step where the AI or an agent generates a
competing set of plausible intelligence conclusions to challenge
the primary findings, mitigating confirmation bias.
"""

import typer
import logging
import json  # <-- ADDED IMPORT
from typing import Optional, List, Dict, Any
from .schemas import AlternativeHypothesisResult, Hypothesis
from .utils import save_or_print_results, console
from .database import get_aggregated_data_for_target, save_scan_to_db
from .project_manager import resolve_target
from .ai_core import generate_swot_from_data  # Re-using the AI core
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)

alternative_hypothesis_app = typer.Typer()


def generate_alternative_hypotheses(target: str) -> AlternativeHypothesisResult:
    """
    Generates competing hypotheses based on aggregated project data.

    Args:
        target (str): The primary target of the analysis.

    Returns:
        AlternativeHypothesisResult: A Pydantic model with competing conclusions.
    """
    logger.info(f"Generating alternative hypotheses for {target}")
    
    # 1. Gather all existing data and key findings for the target
    aggregated_data = get_aggregated_data_for_target(target)

    if not aggregated_data:
        return AlternativeHypothesisResult(
            target=target, error="No historical data found for target."
        )

    # 2. Synthesize key findings into a summary
    # This is a simplified summary. A real one would be more sophisticated.
    findings_summary = []
    modules = aggregated_data.get("modules", {})
    
    if "behavioral_psych_profile" in modules:
        traits = modules["behavioral_psych_profile"].get("profile_summary", {}).get("dominant_traits", [])
        if traits:
            findings_summary.append(f"Primary Finding: Target's dominant behavioral trait is '{traits[0]}'.")

    if "vulnerability_scanner" in modules:
        vulns = modules["vulnerability_scanner"].get("vulnerabilities", [])
        if vulns:
            findings_summary.append(f"Primary Finding: Target has {len(vulns)} critical vulnerabilities.")
        else:
            # If no vulns found, that is also a finding
            findings_summary.append("Primary Finding: No critical vulnerabilities were detected on scanned assets.")


    if not findings_summary:
        return AlternativeHypothesisResult(
            target=target,
            error="No primary findings found in database to challenge.",
        )
    
    full_text_findings = "\n".join(findings_summary)

    # 3. Use AI core to challenge these findings
    api_key = API_KEYS.google_api_key
    if not api_key:
        return AlternativeHypothesisResult(
            target=target, error="Google API key not configured."
        )

    prompt = f"""
    As a 'Red Team' intelligence analyst, your job is to mitigate confirmation bias.
    You will be given a set of primary intelligence findings for a target.
    Your task is to generate 2-3 plausible, competing alternative hypotheses that also fit the available data.
    
    For each alternative hypothesis, you must provide:
    1.  "hypothesis": The competing conclusion.
    2.  "justification": Why this alternative could be true (e.g., "The data could be misinterpreted," "It could be a deception operation").
    3.  "intelligence_gap": What new information would be needed to confirm or deny this alternative?

    **Primary Findings for Target '{target}':**
    {full_text_findings}

    Return your analysis as a single, valid JSON object with a key "hypotheses",
    which contains a list of the hypothesis objects you generated.
    
    Example JSON format:
    {{
        "hypotheses": [
            {{
                "hypothesis": "The 'vulnerabilities' are a honeypot.",
                "justification": "The target is security-mature, making open ports suspicious. This could be a deception to trap attackers.",
                "intelligence_gap": "Need to analyze data exfiltration from these ports. Is any real data exposed?"
            }},
            {{
                "hypothesis": "The 'dominant trait' is a public persona, not a real driver.",
                "justification": "Public communications are curated. The calm trait may be a PR strategy, while internal comms (which we lack) might show panic.",
                "intelligence_gap": "Need HUMINT or internal communications to verify if private behavior matches the public persona."
            }}
        ]
    }}
    
    Return ONLY the valid JSON object and no other text.
    """

    # We re-use generate_swot_from_data as a generic AI text generator
    ai_result = generate_swot_from_data(prompt, api_key)
    
    if ai_result.error:
        return AlternativeHypothesisResult(
            target=target, error=f"AI analysis failed: {ai_result.error}"
        )

    # --- START REAL IMPLEMENTATION ---
    # Parse the AI's JSON response instead of using dummy data
    try:
        json_text = ai_result.analysis_text.strip().lstrip("```json").rstrip("```")
        parsed_data = json.loads(json_text)
        
        hypotheses_data = parsed_data.get("hypotheses", [])
        
        hypotheses = [
            Hypothesis.model_validate(h) for h in hypotheses_data
        ]

        if not hypotheses:
             return AlternativeHypothesisResult(
                target=target,
                error="AI generated an empty or invalid hypothesis list.",
                ai_raw_analysis=ai_result.analysis_text
            )

        return AlternativeHypothesisResult(
            target=target,
            primary_findings_summary=full_text_findings,
            alternative_hypotheses=hypotheses,
            ai_raw_analysis=ai_result.analysis_text, # Keep raw text for audit
        )
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI JSON response for hypothesis: {e}")
        logger.debug(f"Raw LLM response: {ai_result.analysis_text}")
        return AlternativeHypothesisResult(
            target=target,
            error=f"AI response was not valid JSON. See logs for details.",
            ai_raw_analysis=ai_result.analysis_text
        )
    # --- END REAL IMPLEMENTATION ---


@alternative_hypothesis_app.command("run")
def run_alternative_hypothesis(
    target: Optional[str] = typer.Argument(
        None, help="The target to analyze. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Generates competing hypotheses to challenge primary intelligence findings.
    """
    target_name = resolve_target(target)
    
    with console.status(
        f"[bold cyan]Generating alternative hypotheses for {target_name}...[/bold cyan]"
    ):
        results_model = generate_alternative_hypotheses(target_name)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    
    # Don't save to DB if there was an error
    if not results_model.error:
        save_scan_to_db(
            target=target_name, module="alternative_hypothesis", data=results_dict
        )