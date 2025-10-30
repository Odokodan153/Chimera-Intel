"""
Module for PESTEL (Political, Economic, Social, Technological, Environmental, Legal) analysis.

This module uses the AI core to synthesize aggregated OSINT data into a strategic
PESTEL framework, providing high-level insights into a target's operating environment.
"""

import typer
import json
from rich.markdown import Markdown
import logging
from typing import Optional

from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console
from chimera_intel.core.schemas import PESTELAnalysisResult
from chimera_intel.core.ai_core import (
    generate_swot_from_data,
)  # Re-using for general AI generation
from .project_manager import resolve_target

logger = logging.getLogger(__name__)


def generate_pestel_analysis(
    aggregated_data: dict, api_key: str
) -> PESTELAnalysisResult:
    """
    Uses a Generative AI model to create a PESTEL analysis from aggregated OSINT data.

    Args:
        aggregated_data (dict): The combined OSINT data for the target.
        api_key (str): The Google AI API key.

    Returns:
        PESTELAnalysisResult: A Pydantic model containing the AI-generated analysis.
    """
    if not api_key:
        return PESTELAnalysisResult(
            analysis_text="", error="GOOGLE_API_KEY not found in .env file."
        )
    data_str = json.dumps(aggregated_data, indent=2, default=str)
    target_name = aggregated_data.get("target", "the target")

    prompt = f"""
    As an expert strategic analyst, your task is to synthesize the following OSINT data
    for '{target_name}' into a PESTEL (Political, Economic, Social, Technological,
    Environmental, Legal) analysis.

    Based ONLY on the provided data, identify key factors for each category.
    Present the entire output in Markdown format. For each of the six categories,
    provide 2-3 bullet points summarizing the most significant factors. If no data
    is available for a category, state "No specific data available."

    OSINT DATA:
    ```json
    {data_str}
    ```
    """

    try:
        # Re-using the generic text generation function from ai_core
        result = generate_swot_from_data(prompt, api_key)
        if result.error:
            raise Exception(result.error)
        return PESTELAnalysisResult(analysis_text=result.analysis_text)
    except Exception as e:
        logger.error(
            f"An error occurred with the Google AI API during PESTEL generation: {e}"
        )
        return PESTELAnalysisResult(
            analysis_text="", error=f"An error occurred with the Google AI API: {e}"
        )


# --- Typer CLI Application ---


pestel_analyzer_app = typer.Typer()


@pestel_analyzer_app.command("run")
def run_pestel_analysis(
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="The target to analyze. Uses active project if not provided.",
    ),
):
    """
    Generates an AI-powered PESTEL analysis from all aggregated data for a target.
    """
    target_name = resolve_target(target, required_assets=["domain", "company_name"])
    logger.info(f"Generating PESTEL analysis for target: {target_name}")

    aggregated_data = get_aggregated_data_for_target(target_name)
    if not aggregated_data:
        console.print(
            f"[bold red]Error:[/bold red] No historical data found for '{target_name}'. Run scans first."
        )
        raise typer.Exit(code=1)

    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print(
            "[bold red]Error:[/bold red] Google API key (GOOGLE_API_KEY) not found."
        )

        raise typer.Exit(code=1)

    with console.status(
        "[bold cyan]Synthesizing data with AI for PESTEL analysis...[/bold cyan]"
    ):
        pestel_result = generate_pestel_analysis(aggregated_data, api_key)

    console.print(f"\n--- [bold]PESTEL Analysis for {target_name}[/bold] ---\n")
    if pestel_result.error:
        console.print(
            f"[bold red]Error generating analysis:[/bold red] {pestel_result.error}"
        )

        raise typer.Exit(code=1)
    else:
        console.print(Markdown(pestel_result.analysis_text or "No analysis generated."))


if __name__ == "__main__":
    pestel_analyzer_app()
