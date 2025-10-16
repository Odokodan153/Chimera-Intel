"""
Module for the AI-Powered Lead Suggester.

This module analyzes all existing data for a project and suggests the next
logical steps for an intelligence analyst to take.
"""

import typer
import json
import logging

from rich.markdown import Markdown

from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console
from chimera_intel.core.schemas import LeadSuggestionResult
from chimera_intel.core.ai_core import (
    generate_swot_from_data,
)  # Re-using for general AI generation
from .project_manager import get_active_project

logger = logging.getLogger(__name__)


def generate_lead_suggestions(
    aggregated_data: dict, api_key: str
) -> LeadSuggestionResult:
    """
    Uses a Generative AI model to suggest next steps for an investigation.

    Args:
        aggregated_data (dict): The combined OSINT data for the project's target.
        api_key (str): The Google AI API key.

    Returns:
        LeadSuggestionResult: A Pydantic model containing the AI-generated suggestions.
    """
    if not api_key:
        return LeadSuggestionResult(
            suggestions_text="", error="GOOGLE_API_KEY not found in .env file."
        )
    target_name = aggregated_data.get("target", "the target")
    data_str = json.dumps(aggregated_data.get("modules", {}), indent=2, default=str)

    prompt = f"""
    As a senior intelligence analyst and investigation manager, your task is to review the
    following OSINT data summary for the target '{target_name}' and suggest the next
    logical steps for the investigation.

    Analyze the existing data to identify gaps, interesting findings, and potential new
    avenues of inquiry. Based on your analysis, provide a list of 3 to 5 concrete,
    actionable intelligence leads.

    For each lead, provide:
    1.  A clear, concise title for the lead.
    2.  A brief justification explaining *why* it's a good next step based on the existing data.
    3.  The specific Chimera Intel command that should be run to pursue this lead.

    Present the entire output in Markdown format.

    **Existing OSINT Data Summary:**
    ```json
    {data_str}
    ```
    """

    try:
        # Re-using the generic text generation function from ai_core

        result = generate_swot_from_data(prompt, api_key)
        if result.error:
            raise Exception(result.error)
        return LeadSuggestionResult(suggestions_text=result.analysis_text)
    except Exception as e:
        logger.error(
            f"An error occurred with the Google AI API during lead suggestion: {e}"
        )
        return LeadSuggestionResult(
            suggestions_text="", error=f"An error occurred with the Google AI API: {e}"
        )


# --- Typer CLI Application ---


lead_suggester_app = typer.Typer()


@lead_suggester_app.command("run")
def run_lead_suggestion(
    no_rich: bool = typer.Option(
        False, "--no-rich", help="Disable rich text formatting."
    )
):
    """
    Analyzes the active project and suggests next steps for the investigation.
    """
    try:
        active_project = get_active_project()
        if not active_project:
            typer.echo(
                "Error: No active project set. Use 'chimera project use <name>' first.",
                err=True,
            )
            raise typer.Exit(code=1)
        target_name = active_project.company_name or active_project.domain
        if not target_name:
            typer.echo(
                "Error: Active project has no target (domain or company name) set.",
                err=True,
            )
            raise typer.Exit(code=1)
        logger.info(
            f"Generating lead suggestions for project: {active_project.project_name}"
        )

        aggregated_data = get_aggregated_data_for_target(target_name)
        if not aggregated_data:
            typer.echo(
                f"Error: No historical data found for '{target_name}'. Run scans first.",
                err=True,
            )
            raise typer.Exit(code=1)
        api_key = API_KEYS.google_api_key
        if not api_key:
            typer.echo("Error: Google API key (GOOGLE_API_KEY) not found.", err=True)
            raise typer.Exit(code=1)
        with console.status(
            "[bold cyan]AI is analyzing the case file to suggest next steps...[/bold cyan]",
            disable=no_rich,
        ):
            suggestion_result = generate_lead_suggestions(aggregated_data, api_key)
        if not no_rich:
            console.print(
                f"\n--- [bold]Suggested Intelligence Leads for {active_project.project_name}[/bold] ---\n"
            )
        if suggestion_result.error:
            typer.echo(
                f"Error generating suggestions: {suggestion_result.error}", err=True
            )
            raise typer.Exit(code=1)
        else:
            output_text = (
                suggestion_result.suggestions_text or "No suggestions generated."
            )
            if no_rich:
                typer.echo(output_text)
            else:
                console.print(Markdown(output_text))
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)
