"""
Module for Behavioral and Psychographic OSINT.

Analyzes the language used in a company's public communications to infer
its culture, strategic focus, and other behavioral traits.
"""

import typer
import logging
import math
from collections import Counter
from typing import Optional, List, Dict, Any
from .schemas import PsychographicProfileResult, BehavioralSignal, NarrativeEntropy
from .utils import save_or_print_results, console
from .database import get_aggregated_data_for_target, save_scan_to_db
from .project_manager import resolve_target
from .ai_core import classify_text_zero_shot

logger = logging.getLogger(__name__)

BEHAVIORAL_LABELS = {
    "Innovation & R&D": [
        "innovation",
        "research",
        "develop",
        "breakthrough",
        "future",
        "patent",
    ],
    "Aggressive Marketing": [
        "growth",
        "dominate",
        "leader",
        "best",
        "disrupt",
        "game-changing",
    ],
    "Corporate Social Responsibility": [
        "sustainability",
        "ethical",
        "community",
        "diversity",
        "environment",
    ],
    "Risk Aversion & Stability": [
        "stable",
        "secure",
        "reliable",
        "compliance",
        "standard",
        "proven",
    ],
    "Hiring & Expansion": [
        "hiring",
        "join us",
        "new office",
        "expanding",
        "new market",
        "career",
    ],
}


def calculate_narrative_entropy(
    signals: List[BehavioralSignal],
) -> Optional[NarrativeEntropy]:
    """
    Calculates the Shannon entropy of the narrative based on signal types.
    """
    if not signals:
        return None
    type_counts = Counter(s.signal_type for s in signals)
    total_signals = len(signals)
    entropy = 0.0

    for count in type_counts.values():
        probability = count / total_signals
        entropy -= probability * math.log2(probability)
    if entropy < 1.0:
        assessment = "Highly Focused Narrative (Low Entropy)"
    elif entropy < 2.0:
        assessment = "Focused Narrative (Moderate Entropy)"
    else:
        assessment = "Diverse Narrative (High Entropy)"
    top_keywords = [item[0] for item in type_counts.most_common(3)]

    return NarrativeEntropy(
        entropy_score=round(entropy, 4),
        assessment=assessment,
        top_keywords=top_keywords,
    )


def generate_psychographic_profile(target: str) -> PsychographicProfileResult:
    """
    Generates a psychographic profile by analyzing aggregated OSINT data.

    Args:
        target (str): The primary target of the analysis (company name or domain).

    Returns:
        PsychographicProfileResult: A Pydantic model containing the synthesized profile.
    """
    logger.info(f"Generating psychographic profile for {target}")
    aggregated_data = get_aggregated_data_for_target(target)

    if not aggregated_data:
        return PsychographicProfileResult(
            target=target, error="No historical data found for target."
        )
    modules = aggregated_data.get("modules", {})
    signals: List[BehavioralSignal] = []

    # 1. Analyze News Articles

    news_articles = (
        modules.get("business_intel", {}).get("news", {}).get("articles", [])
    )
    for article in news_articles:
        text = f"{article.get('title', '')}. {article.get('description', '')}"
        classification = classify_text_zero_shot(text, list(BEHAVIORAL_LABELS.keys()))
        if classification and classification["scores"][0] > 0.7:  # Confidence threshold
            top_label = classification["labels"][0]
            signals.append(
                BehavioralSignal(
                    source_type="News Article",
                    signal_type=top_label,
                    content=article.get("title", "N/A"),
                    justification=f"Article content strongly aligns with '{top_label}' themes.",
                )
            )
    # 2. Analyze Job Postings

    job_postings = modules.get("job_postings", {}).get("job_postings", [])
    for job_title in job_postings:
        classification = classify_text_zero_shot(
            job_title, list(BEHAVIORAL_LABELS.keys())
        )
        if (
            classification and classification["scores"][0] > 0.6
        ):  # Lower threshold for job titles
            top_label = classification["labels"][0]
            signals.append(
                BehavioralSignal(
                    source_type="Job Posting",
                    signal_type=top_label,
                    content=job_title,
                    justification=f"Job title '{job_title}' suggests a focus on '{top_label}'.",
                )
            )
    # 3. Synthesize Profile Summary

    summary: Dict[str, Any] = {"dominant_traits": []}
    trait_counts: Dict[str, int] = {}
    for signal in signals:
        trait_counts[signal.signal_type] = trait_counts.get(signal.signal_type, 0) + 1
    if trait_counts:
        sorted_traits = sorted(
            trait_counts.items(), key=lambda item: item[1], reverse=True
        )
        summary["dominant_traits"] = [trait[0] for trait in sorted_traits]
    # 4. Calculate Narrative Entropy

    narrative_entropy = calculate_narrative_entropy(signals)

    return PsychographicProfileResult(
        target=target,
        profile_summary=summary,
        behavioral_signals=signals,
        narrative_entropy=narrative_entropy,
    )


# --- Typer CLI Application ---


behavioral_app = typer.Typer()


@behavioral_app.command("psych-profile")
def run_psych_profile(
    target: Optional[str] = typer.Argument(
        None, help="The target to analyze. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes public communications to build a corporate psychographic profile.
    """
    target_name = resolve_target(target, required_assets=["domain", "company_name"])

    with console.status(
        f"[bold cyan]Generating psychographic profile for {target_name}...[/bold cyan]"
    ):
        results_model = generate_psychographic_profile(target_name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="behavioral_psych_profile", data=results_dict
    )
