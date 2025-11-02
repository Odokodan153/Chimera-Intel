"""
Module for Alternative Hypothesis Generation.

A mandatory analytical step where the AI or an agent generates a
competing set of plausible intelligence conclusions to challenge
the primary findings, mitigating confirmation bias.
"""

import typer
import logging
from typing import Optional, List, Dict, Any
from .schemas import AlternativeHypothesisResult, Hypothesis
from .utils import save_or_print_results, console
from .database import get_aggregated_data_for_target, save_scan_to_db
from .project_manager import resolve_target
from .ai_core import generate_swot_from_data
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

    if "vulnerability_scan" in modules:
        vulns = modules["vulnerability_scan"].get("vulnerabilities", [])
        if vulns:
            findings_summary.append(f"Primary Finding: Target has {len(vulns)} critical vulnerabilities.")

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
    
    For each alternative hypothesis, provide:
    1.  **Alternative Hypothesis**: The competing conclusion.
    2.  **Justification**: Why this alternative could be true (e.g., "The data could be misinterpreted," "It could be a deception operation").
    3.  **Intelligence Gap**: What new information would be needed to confirm or deny this alternative?

    **Primary Findings for Target '{target}':**
    {full_text_findings}

    Return your analysis as a structured summary.
    """

    ai_result = generate_swot_from_data(prompt, api_key)
    
    if ai_result.error:
        return AlternativeHypothesisResult(
            target=target, error=f"AI analysis failed: {ai_result.error}"
        )

    # Dummy data for structured fields
    hypotheses = [
        Hypothesis(
            hypothesis="Extracted from AI (e.g., 'The 'vulnerabilities' are a honeypot.')",
            justification="Extracted from AI (e.g., 'The target is security-mature, making open ports suspicious.')",
            intelligence_gap="Extracted from AI (e.g., 'Need to analyze data exfiltration from these ports.')"
        )
    ]

    return AlternativeHypothesisResult(
        target=target,
        primary_findings_summary=full_text_findings,
        alternative_hypotheses=hypotheses,
        ai_raw_analysis=ai_result.analysis_text,
    )


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
    save_scan_to_db(
        target=target_name, module="alternative_hypothesis", data=results_dict
    )