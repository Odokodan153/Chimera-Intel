"""
Disinformation & Synthetic Narrative Mapping Module for Chimera Intel.

Analyzes text from news and social media to detect coordinated 
use of AI-generated prose.
"""

import typer
import logging
import numpy as np
import re
from chimera_intel.core.schemas import SyntheticTextAnalysis,SyntheticNarrativeItem,SyntheticNarrativeMapResult
from typing import Dict, Optional
from chimera_intel.core.narrative_analyzer import track_narrative
from chimera_intel.core.utils import console, save_or_print_results
from .database import save_scan_to_db # Added database import

logger = logging.getLogger(__name__)


def analyze_text_for_synthesis(text: str) -> SyntheticTextAnalysis:
    """
    Runs enhanced heuristics to detect AI-generated prose based on
    statistical properties of the text.
    """
    text_lower = text.lower()
    
    # --- Heuristic 1: High-Confidence Keyword Triggers ---
    # This is a "smoking gun" check.
    ai_phrases = [
        "as an ai language model",
        "i cannot express personal opinions",
        "i do not have beliefs",
        "regenerate response"
    ]
    for phrase in ai_phrases:
        if phrase in text_lower:
            return SyntheticTextAnalysis(
                is_synthetic=True,
                confidence=0.95,
                evidence=f"Contains high-confidence AI disclaimer phrase: '{phrase}'"
            )

    # Clean text for statistical analysis
    words = re.findall(r'\b\w+\b', text_lower)
    if len(words) < 20: # Not enough data to analyze
        return SyntheticTextAnalysis()

    # --- Heuristic 2: Lexical Diversity (Type-Token Ratio) ---
    # AI models can sometimes be repetitive, leading to low lexical diversity.
    total_words = len(words)
    unique_words = len(set(words))
    ttr = unique_words / total_words
    
    # TTR is sensitive to text length; for short texts (< 300 words),
    # a TTR < 0.45 is a potential indicator.
    ttr_score = 0.0
    if total_words < 300 and ttr < 0.45:
        ttr_score = (0.45 - ttr) * 2.0 # Normalize score
    
    # --- Heuristic 3: Sentence Length Uniformity ---
    # Human writing is "bursty" (mix of short and long sentences).
    # AI text can be very uniform, leading to low variance.
    sentences = re.split(r'[.!?]+', text)
    sentence_lengths = [len(s.split()) for s in sentences if len(s.split()) > 0]
    
    if len(sentence_lengths) < 3: # Not enough sentences
        return SyntheticTextAnalysis()

    variance = np.var(sentence_lengths)
    
    # A variance < 5 suggests very high uniformity (e.g., all sentences are 15-20 words).
    variance_score = 0.0
    if variance < 5:
        variance_score = (5 - variance) / 5.0 # Normalize score

    # --- Final Score ---
    # Combine scores, weighting uniformity as a stronger indicator.
    final_confidence = (ttr_score * 0.4) + (variance_score * 0.6)
    
    if final_confidence > 0.6:
        return SyntheticTextAnalysis(
            is_synthetic=True,
            confidence=round(final_confidence, 2),
            evidence=f"High uniformity detected (Low TTR: {ttr:.2f}, Low Sent. Variance: {variance:.2f})"
        )

    return SyntheticTextAnalysis()


def map_synthetic_narrative(query: str) -> SyntheticNarrativeMapResult:
    """
    Analyzes text from news, social media, and forums to detect coordinated
    use of AI-generated prose.
    """
    logger.info(f"Mapping synthetic narrative for query: {query}")
    try:
        # 1. Reuse existing narrative tracker
        # (Assuming narrative_analyzer.track_narrative exists)
        narrative_items = track_narrative(query)
        if not narrative_items:
            return SyntheticNarrativeMapResult(query=query, total_items_found=0, synthetic_items_detected=0)

        result = SyntheticNarrativeMapResult(query=query, total_items_found=len(narrative_items))
        synthetic_count = 0
        synthetic_by_type: Dict[str, int] = {}

        # 2. Analyze each item for synthetic prose
        for item in narrative_items:
            # Fallback for item content
            item_content = item.get("content", "")
            if not item_content:
                continue

            analysis = analyze_text_for_synthesis(item_content)
            
            synth_item = SyntheticNarrativeItem(
                source=item.get("source", "Unknown"),
                type=item.get("type", "Unknown"),
                content=item_content,
                sentiment=item.get("sentiment", 0.0),
                synthetic_analysis=analysis
            )
            
            if analysis.is_synthetic:
                synthetic_count += 1
                item_type = item.get("type", "Unknown")
                synthetic_by_type[item_type] = synthetic_by_type.get(item_type, 0) + 1
                result.synthetic_narrative_map.append(synth_item)

        result.synthetic_items_detected = synthetic_count
        result.synthetic_items_by_type = synthetic_by_type
        return result

    except Exception as e:
        logger.error(f"Error in synthetic narrative mapping: {e}", exc_info=True)
        return SyntheticNarrativeMapResult(query=query, error=str(e))

# --- CLI Application ---

disinformation_app = typer.Typer(
    name="disinfo",
    help="Disinformation and Synthetic Narrative Analysis.",
)

@disinformation_app.command(
    "synthetic-narrative-map",
    help="Detect AI-generated prose amplifying a narrative.",
)
def run_synthetic_narrative_map(
    query: str = typer.Argument(..., help="The narrative, keyword, or phrase to track."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes news and social media to find where AI-generated text
    is being used to amplify a specific narrative.
    """
    console.print(f"[bold cyan]Mapping synthetic narrative for:[/bold cyan] '{query}'")
    result = map_synthetic_narrative(query)
    
    result_dump = result.model_dump(exclude_none=True)
    save_or_print_results(result_dump, output_file)
    
    # Save the main result to the DB
    save_scan_to_db(target=query, module="synthetic_narrative_map", data=result_dump)
    
    if result.synthetic_items_detected > 0:
        console.print(f"\n[bold yellow]Warning:[/bold yellow] Detected [bold red]{result.synthetic_items_detected}[/bold red] suspected synthetic items.")
        console.print(f"Breakdown: {result.synthetic_items_by_type}")


# --- NEW CLI COMMAND START ---
# This new command reuses the existing `map_synthetic_narrative` function
# as requested by "Disinformation-Audit".

@disinformation_app.command(
    "audit",
    help="Passively monitor for disinformation campaigns against a target.",
)
def run_disinformation_audit(
    target: str = typer.Argument(..., help="The brand, executive, or keyword to audit."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Passively monitors social, news, and forum data for coordinated
    information campaigns or narrative manipulation against the target.
    
    This command is an alias for 'synthetic-narrative-map'
    to fit the 'Disinformation-Audit' use case.
    """
    console.print(f"[bold cyan]Running Disinformation Audit for:[/bold cyan] '{target}'")
    # Reuse the exact same function as synthetic-narrative-map
    result = map_synthetic_narrative(target)
    
    result_dump = result.model_dump(exclude_none=True)
    save_or_print_results(result_dump, output_file)
    
    # Save the main result to the DB
    save_scan_to_db(target=target, module="disinformation_audit", data=result_dump)

    if result.synthetic_items_detected > 0:
        console.print(f"\n[bold yellow]Audit Warning:[/bold yellow] Detected [bold red]{result.synthetic_items_detected}[/bold red] suspected synthetic items amplifying this narrative.")
        console.print(f"Breakdown: {result.synthetic_items_by_type}")
    else:
        console.print(f"\n[bold green]Audit Complete:[/bold green] No synthetic amplification detected.")
# --- NEW CLI COMMAND END ---