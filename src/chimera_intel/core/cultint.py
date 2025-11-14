"""
CULTINT (Cultural Intelligence) Module for Chimera Intel.

Analyzes cultural trends, narratives, and sentiments from various data sources
to provide insights into the cultural landscape surrounding a target.
"""

import typer
from typing import Optional, Dict, Any
from .database import get_aggregated_data_for_target
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS
from .utils import console

cultint_app = typer.Typer(
    name="cultint",
    help="Performs Cultural Intelligence (CULTINT) analysis.",
)


def analyze_cultural_narrative(target: str) -> Optional[Dict[str, Any]]:
    """
    Analyzes the cultural narrative of a target using aggregated OSINT data.
    """
    console.print(
        f"[bold cyan]Analyzing cultural narrative for {target}...[/bold cyan]"
    )

    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        raise typer.Exit(code=1)
    # Fetch aggregated data from modules that are relevant to cultural analysis

    aggregated_data = get_aggregated_data_for_target(target)

    if not aggregated_data:
        console.print(
            f"[yellow]Warning:[/] No relevant data sources (social media, news, HR intel) found for '{target}' to analyze cultural narrative."
        )
        raise typer.Exit(code=0)

    # Filter for modules that provide cultural context

    cultural_data_sources = {
        "social_media": aggregated_data.get("modules", {}).get("social_analyzer"),
        "news_media": aggregated_data.get("modules", {})
        .get("business_intel", {})
        .get("news"),
        "employee_sentiment": aggregated_data.get("modules", {}).get(
            "corporate_hr_intel"
        ),
    }

    # Remove empty sources

    cultural_data_sources = {k: v for k, v in cultural_data_sources.items() if v}

    if not cultural_data_sources:
        console.print(
            f"[yellow]Warning:[/] No relevant data sources (social media, news, HR intel) found for '{target}' to analyze cultural narrative."
        )
        raise typer.Exit(code=0)
    prompt = f"""
    As a cultural intelligence analyst, analyze the following data collected on {target}.
    Based on this information, provide a summary of the dominant cultural narratives, sentiments, and values expressed.
    Consider the perspectives from social media, news coverage, and internal employee sentiment.

    **Collected Data:**
    {cultural_data_sources}
    """

    ai_result = generate_swot_from_data(prompt, api_key)

    if ai_result.error:
        console.print(f"[bold red]AI Analysis Error:[/bold red] {ai_result.error}")
        raise typer.Exit(code=1)
    return {"cultural_narrative_analysis": ai_result.analysis_text}


@cultint_app.command("analyze")
def run_cultint_analysis(
    target: str = typer.Argument(
        ..., help="The target entity (e.g., a company name or domain) to analyze."
    )
):
    """
    Performs cultural intelligence analysis on a given target.
    """
    try:
        result = analyze_cultural_narrative(target)
        if result:
            console.print(
                f"\n[bold green]Cultural Narrative Analysis for {target}:[/bold green]"
            )
            console.print(result["cultural_narrative_analysis"])
    except typer.Exit as e:
        # This logic is correct: it allows clean exits (code=0) to pass silently
        # and re-raises error exits (like code=1).
        if e.exit_code == 0:
            # This is a clean exit, so we don't need to do anything.
            return
        # This is an error exit, so we re-raise the exception.
        raise
