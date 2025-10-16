"""
Module for Competitive Analysis.

This module uses the AI core to generate a side-by-side strategic comparison
of two targets based on previously saved scan data.
"""

import typer
import json
import logging

from rich.markdown import Markdown

from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console
from chimera_intel.core.schemas import CompetitiveAnalysisResult
from chimera_intel.core.ai_core import (
    generate_swot_from_data,
)  # Re-using for general AI generation

logger = logging.getLogger(__name__)


def generate_competitive_analysis(
    target_a_data: dict, target_b_data: dict, api_key: str
) -> CompetitiveAnalysisResult:
    """
    Uses a Generative AI model to compare two sets of OSINT data.

    Args:
        target_a_data (dict): The aggregated OSINT data for the first target.
        target_b_data (dict): The aggregated OSINT data for the second target.
        api_key (str): The Google AI API key.

    Returns:
        CompetitiveAnalysisResult: A Pydantic model containing the AI-generated analysis.
    """
    if not api_key:
        return CompetitiveAnalysisResult(
            analysis_text="", error="GOOGLE_API_KEY not found in .env file."
        )
    target_a_name = target_a_data.get("target", "Target A")
    target_b_name = target_b_data.get("target", "Target B")

    # Stringify the JSON data for the prompt

    target_a_str = json.dumps(target_a_data, indent=2, default=str)
    target_b_str = json.dumps(target_b_data, indent=2, default=str)

    prompt = f"""
    As an expert competitive intelligence analyst, your task is to conduct a side-by-side
    comparison of two companies, '{target_a_name}' and '{target_b_name}', based ONLY on the
    provided OSINT data.

    Present the entire output in Markdown format. Create a main heading for the comparison.
    For each of the following categories, provide a brief, comparative analysis in a bulleted list,
    highlighting the key strategic differences, advantages, and disadvantages for each company.

    1.  **Technology & Infrastructure:** Compare their technology stacks, subdomains, and IP footprints. Which company appears more modern or has a larger digital presence?
    2.  **Market Position & News Flow:** Compare their news coverage, patents, and financial data (if available). Which company seems to have a stronger market position or momentum?
    3.  **Security Posture:** Compare their vulnerability scans, data breach history, and web security grades. Which company appears to have a more robust security posture?
    4.  **Strategic Outlook (Conclusion):** Provide a concluding paragraph summarizing which company appears to have a competitive advantage and why.

    **Data for {target_a_name}:**
    ```json
    {target_a_str}
    ```

    **Data for {target_b_name}:**
    ```json
    {target_b_str}
    ```
    """

    try:
        # Re-using the generic text generation function from ai_core

        result = generate_swot_from_data(prompt, api_key)
        if result.error:
            raise Exception(result.error)
        return CompetitiveAnalysisResult(analysis_text=result.analysis_text)
    except Exception as e:
        logger.error(
            f"An error occurred with the Google AI API during competitive analysis: {e}"
        )
        return CompetitiveAnalysisResult(
            analysis_text="", error=f"An error occurred with the Google AI API: {e}"
        )


# --- Typer CLI Application ---


competitive_analyzer_app = typer.Typer()


@competitive_analyzer_app.command("run")
def run_competitive_analysis(
    target_a: str = typer.Argument(
        ..., help="The first target to compare (domain or company name)."
    ),
    target_b: str = typer.Argument(
        ..., help="The second target to compare (domain or company name)."
    ),
):
    """
    Generates an AI-powered competitive analysis between two targets.
    """
    logger.info(
        f"Generating competitive analysis between '{target_a}' and '{target_b}'."
    )

    # Fetch aggregated data for both targets

    console.print("[bold cyan]Fetching historical data for both targets...[/bold cyan]")
    target_a_data = get_aggregated_data_for_target(target_a)
    target_b_data = get_aggregated_data_for_target(target_b)

    if not target_a_data or not target_b_data:
        console.print(
            "[bold red]Error:[/bold red] Could not retrieve historical data for one or both targets. Ensure scans have been run for both."
        )
        raise typer.Exit(1)
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print(
            "[bold red]Error:[/bold red] Google API key (GOOGLE_API_KEY) not found."
        )
        raise typer.Exit(1)
    console.print(
        "[bold cyan]Synthesizing data with AI for competitive analysis...[/bold cyan]"
    )
    comp_result = generate_competitive_analysis(target_a_data, target_b_data, api_key)

    console.print(
        f"\n--- [bold]Competitive Analysis: {target_a} vs. {target_b}[/bold] ---\n"
    )
    if comp_result.error:
        console.print(
            f"[bold red]Error generating analysis:[/bold red] {comp_result.error}"
        )
        raise typer.Exit(1)
    else:
        console.print(Markdown(comp_result.analysis_text or "No analysis generated."))
