"""
Module for the AI-Powered Intelligence Briefing Generator.

This module automates the final step of the intelligence lifecycle by generating
a complete, multi-page narrative report from all data gathered for a project.
"""

import typer
import json
import logging

from rich.markdown import Markdown

from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console
from chimera_intel.core.schemas import BriefingResult
from chimera_intel.core.ai_core import generate_swot_from_data
from .project_manager import get_active_project

logger = logging.getLogger(__name__)


def generate_intelligence_briefing(
    aggregated_data: dict, api_key: str
) -> BriefingResult:
    """
    Uses a Generative AI model to write a full intelligence briefing.

    Args:
        aggregated_data (dict): The combined OSINT data for the project's target.
        api_key (str): The Google AI API key.

    Returns:
        BriefingResult: A Pydantic model containing the AI-generated report.
    """
    if not api_key:
        return BriefingResult(
            briefing_text="", error="GOOGLE_API_KEY not found in .env file."
        )
    target_name = aggregated_data.get("target", "the target")
    data_str = json.dumps(aggregated_data.get("modules", {}), indent=2, default=str)

    prompt = f"""
    As a senior intelligence director, your task is to write a comprehensive, multi-page
    intelligence briefing for executive leadership regarding the target '{target_name}'.
    Synthesize all the provided OSINT data into a polished, narrative report.

    The report must be in Markdown format and include the following sections:

    1.  **Executive Summary:** A high-level overview of the most critical findings and the overall strategic assessment of the target.
    2.  **Digital Footprint & Attack Surface:** An analysis of their external-facing infrastructure, including key domains, IPs, and technologies.
    3.  **Corporate & Business Intelligence:** An assessment of their business strategy, market position, and recent activities based on financial data, news, and patents.
    4.  **Security Posture Assessment:** A summary of their security weaknesses, including known vulnerabilities, data breach history, and web security misconfigurations.
    5.  **Strategic Outlook & Recommendations:** A forward-looking analysis of their likely future actions and strategic recommendations for our organization.

    Base your entire analysis *only* on the provided data. Do not invent information.

    **Comprehensive OSINT Data File:**
    ```json
    {data_str}
    ```
    """

    try:
        result = generate_swot_from_data(prompt, api_key)
        if result.error:
            raise Exception(result.error)
        return BriefingResult(briefing_text=result.analysis_text)
    except Exception as e:
        logger.error(
            f"An error occurred with the Google AI API during briefing generation: {e}"
        )
        return BriefingResult(
            briefing_text="", error=f"An error occurred with the Google AI API: {e}"
        )


# --- Typer CLI Application ---


present_app = typer.Typer()


@present_app.command("briefing")
def run_briefing_generation():
    """
    Generates a full, multi-page intelligence briefing for the active project.
    """
    active_project = get_active_project()
    if not active_project:
        console.print(
            "[bold red]Error:[/bold red] No active project set. Use 'chimera project use <name>' first."
        )
        raise typer.Exit(code=1)
    target_name = active_project.company_name or active_project.domain
    if not target_name:
        console.print(
            "[bold red]Error:[/bold red] Active project has no target (domain or company name) set."
        )
        raise typer.Exit(code=1)
    logger.info(
        f"Generating intelligence briefing for project: {active_project.project_name}"
    )

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
        "[bold cyan]AI is generating the executive briefing... This may take a moment.[/bold cyan]"
    ):
        briefing_result = generate_intelligence_briefing(aggregated_data, api_key)
    console.print(
        f"\n--- [bold]Intelligence Briefing: {active_project.project_name}[/bold] ---\n"
    )
    if briefing_result.error:
        console.print(
            f"[bold red]Error generating briefing:[/bold red] {briefing_result.error}"
        )
        raise typer.Exit(code=1)
    else:
        console.print(
            Markdown(briefing_result.briefing_text or "No briefing generated.")
        )
