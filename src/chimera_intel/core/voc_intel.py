"""
Module for Voice of Customer (VoC) & Reviews Intelligence.

Analyzes collections of customer reviews (e.g., from app stores,
e-commerce sites) to extract sentiment, recurring themes, feature
requests, and complaints.
"""

import typer
import logging
import json
from typing import List, Optional, Dict
from .schemas import (
    VoCInsight,
    VoCAnalysisResult,
)
from .gemini_client import GeminiClient
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target
from .sentiment_time_series import run_sentiment_time_series
from .topic_clusterer import run_topic_clustering

logger = logging.getLogger(__name__)
gemini_client = GeminiClient()
voc_intel_app = typer.Typer()

# --- Core Logic ---

def _extract_detailed_insights_ai(
    documents: List[Dict[str, str]]
) -> List[VoCInsight]:
    """
    Uses an LLM to extract specific features, complaints, and praises
    from a batch of documents.
    """
    logger.info(f"Extracting detailed insights from {len(documents)} documents.")
    insights = []
    
    # Batch documents to avoid overly long prompts
    # In a real-world scenario, you might process one by one or in small batches.
    # For this example, we'll create one large prompt.
    
    doc_snippets = []
    for i, doc in enumerate(documents):
        content = doc.get("content", "")
        if content:
            hint = content[:200] + "..." if len(content) > 200 else content
            doc_snippets.append(f"<review doc_id=\"{i}\">\n{hint}\n</review>")
            
    if not doc_snippets:
        return []

    all_snippets_str = "\n".join(doc_snippets)

    prompt = f"""
You are a "Voice of Customer" analyst. Your job is to extract actionable
insights from a list of customer reviews.

Analyze the following reviews:
{all_snippets_str}

**Instructions:**
Identify all specific **Complaints**, **Feature Requests**, and **Praises**.
Return your analysis as a single, valid JSON object with a key "insights".
"insights" should be a list of objects, where each object has:
- "category": (string) "Complaint", "Feature Request", or "Praise".
- "topic": (string) The specific topic (e.g., "Login Button", "App Speed", "Battery Drain").
- "sentiment": (string) "Positive", "Negative", or "Neutral".
- "quote": (string) The exact quote from the review that triggered this.

If no specific insights are found, return: {{"insights": []}}
Return ONLY the valid JSON object.
"""

    llm_response = gemini_client.generate_response(prompt)
    if not llm_response:
        logger.warning("LLM call for VoC insights returned empty.")
        return []
    
    try:
        response_json = json.loads(llm_response)
        parsed_insights = response_json.get("insights", [])
        
        for insight_data in parsed_insights:
            insights.append(VoCInsight.model_validate(insight_data))
            
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        logger.error(f"Failed to parse LLM VoC response: {e}")
        logger.debug(f"Raw LLM response: {llm_response}")

    return insights


def run_voc_analysis(
    target: str, documents: List[Dict[str, str]]
) -> VoCAnalysisResult:
    """
    Runs a full VoC analysis pipeline.

    Args:
        target (str): The product, service, or brand being analyzed.
        documents (List[Dict[str, str]]): List of reviews, each with
                                           "timestamp" and "content".

    Returns:
        VoCAnalysisResult: The combined analysis.
    """
    logger.info(f"Starting VoC analysis for target: {target}")

    # 1. Run Sentiment Time Series (Re-used)
    logger.info("Running sentiment analysis...")
    sentiment_results = run_sentiment_time_series(target, documents)

    # 2. Run Topic Clustering (Re-used)
    logger.info("Running topic clustering...")
    topic_results = run_topic_clustering(documents)

    # 3. Run new Feature/Complaint Extraction
    logger.info("Extracting detailed insights...")
    extracted_insights = _extract_detailed_insights_ai(documents)

    return VoCAnalysisResult(
        target=target,
        total_reviews_analyzed=len(documents),
        sentiment_analysis=sentiment_results,
        top_themes=topic_results,
        extracted_insights=extracted_insights
    )


@voc_intel_app.command("run")
def run_voc_analysis_cli(
    target: Optional[str] = typer.Argument(
        None, help="The target/product. Uses active project if not provided."
    ),
    input_file: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON file containing a list of objects, "
             "each with 'timestamp' and 'content' keys.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes customer reviews for sentiment, topics, and actionable insights.
    """
    target_name = resolve_target(target, required_assets=[])

    try:
        with open(input_file, "r") as f:
            documents = json.load(f)
        if not isinstance(documents, list):
            raise ValueError("Input file must contain a JSON list.")
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] Input file not found at '{input_file}'")
        raise typer.Exit(code=1)
    except (json.JSONDecodeError, ValueError) as e:
        console.print(f"[bold red]Error:[/] Invalid JSON in file '{input_file}': {e}")
        raise typer.Exit(code=1)

    with console.status(
        f"[bold cyan]Running VoC analysis for {target_name}...[/bold cyan]"
    ):
        results_model = run_voc_analysis(target_name, documents)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="voc_intel", data=results_dict
    )