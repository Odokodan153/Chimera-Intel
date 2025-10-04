"""
Module for the AI-Powered Intelligence Briefing Generator.

This module automates the final step of the intelligence lifecycle by generating
a complete, multi-page narrative report from all data gathered for a project.
"""

import typer
import json
import logging
from typing import Literal
from rich.markdown import Markdown
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console
from chimera_intel.core.schemas import BriefingResult
from chimera_intel.core.ai_core import generate_swot_from_data
from .project_manager import get_active_project

logger = logging.getLogger(__name__)

# --- Template Prompts ---


TEMPLATES = {
    "ciso_daily": {
        "title": "CISO Daily Security Briefing",
        "prompt": """
        As a senior cybersecurity advisor, your task is to write a concise daily security briefing for the CISO regarding the target '{target_name}'.
        Focus on the most critical and recent threats, vulnerabilities, and security posture changes.

        The report must be in Markdown format and include the following sections:

        1.  **Threat Horizon:** What are the most critical new vulnerabilities, code leaks, or dark web mentions?
        2.  **Attack Surface Changes:** Have any new subdomains, open ports, or web technologies been detected in the last 24 hours?
        3.  **Breach & Credential Exposure:** Summary of any new findings related to data breaches or compromised credentials.
        4.  **Immediate Recommendations:** A prioritized list of actions that need to be taken today.

        Base your entire analysis *only* on the provided data. Do not invent information.
        """,
    },
    "ceo_weekly": {
        "title": "CEO Weekly Competitive & Strategic Landscape",
        "prompt": """
        As a chief strategy officer, your task is to write a high-level weekly intelligence briefing for the CEO regarding the target '{target_name}'.
        Synthesize all the provided OSINT data into a polished, narrative report focusing on business impact, risk, and opportunities.

        The report must be in Markdown format and include the following sections:

        1.  **Executive Summary:** A high-level overview of the most critical findings and the overall strategic assessment of the target.
        2.  **Competitive Moves:** Analysis of competitor activities, including new patents, financial news, and strategic signals from hiring trends.
        3.  **Reputation & Sentiment:** How is the target's brand being perceived? Summarize recent news and social media sentiment.
        4.  **Strategic Outlook & Opportunities:** A forward-looking analysis of their likely future actions and potential opportunities or risks for our organization.

        Base your entire analysis *only* on the provided data. Do not invent information.
        """,
    },
}


def generate_intelligence_briefing(
    aggregated_data: dict,
    api_key: str,
    template: str = "ceo_weekly",
) -> BriefingResult:
    """
    Uses a Generative AI model to write a full intelligence briefing based on a template.

    Args:
        aggregated_data (dict): The combined OSINT data for the project's target.
        api_key (str): The Google AI API key.
        template (str): The name of the briefing template to use.

    Returns:
        BriefingResult: A Pydantic model containing the AI-generated report.
    """
    if not api_key:
        return BriefingResult(
            briefing_text="", error="GOOGLE_API_KEY not found in .env file."
        )
    template_config = TEMPLATES.get(template)
    if not template_config:
        return BriefingResult(
            briefing_text="", error=f"Template '{template}' not found."
        )
    target_name = aggregated_data.get("target", "the target")
    data_str = json.dumps(aggregated_data.get("modules", {}), indent=2, default=str)

    prompt_template = template_config["prompt"]
    prompt = f"{prompt_template}\n\n**Comprehensive OSINT Data File:**\n```json\n{data_str}\n```"

    try:
        result = generate_swot_from_data(prompt, api_key)
        if result.error:
            raise Exception(result.error)
        return BriefingResult(
            briefing_text=result.analysis_text, title=template_config["title"]
        )
    except Exception as e:
        logger.error(
            f"An error occurred with the Google AI API during briefing generation: {e}"
        )
        return BriefingResult(
            briefing_text="", error=f"An error occurred with the Google AI API: {e}"
        )


# --- Typer CLI Application ---


briefing_app = typer.Typer()


@briefing_app.command("generate")
def run_briefing_generation(
    template: str = typer.Option(
        "ceo_weekly",
        "--template",
        "-t",
        help="The template to use for the briefing (e.g., 'ciso_daily', 'ceo_weekly').",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to save the briefing as a PDF file.",
    ),
):
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
        briefing_result = generate_intelligence_briefing(
            aggregated_data, api_key, template
        )
    if briefing_result.error:
        console.print(
            f"[bold red]Error generating briefing:[/bold red] {briefing_result.error}"
        )
        raise typer.Exit(code=1)
    # --- Output Handling ---

    if output:
        doc = SimpleDocTemplate(output)
        styles = getSampleStyleSheet()
        story = [Paragraph(briefing_result.title, styles["h1"]), Spacer(1, 0.25 * inch)]
        # Basic markdown to reportlab conversion

        for line in (briefing_result.briefing_text or "").split("\n"):
            if line.startswith("# "):
                story.append(Paragraph(line.lstrip("# "), styles["h1"]))
            elif line.startswith("## "):
                story.append(Paragraph(line.lstrip("## "), styles["h2"]))
            elif line.startswith("### "):
                story.append(Paragraph(line.lstrip("### "), styles["h3"]))
            elif line.startswith("* "):
                story.append(Paragraph(f"• {line.lstrip('* ')}", styles["Normal"]))
            else:
                story.append(Paragraph(line, styles["Normal"]))
            story.append(Spacer(1, 0.1 * inch))
        doc.build(story)
        console.print(f"[bold green]Briefing saved to:[/bold green] {output}")
    else:
        console.print(
            f"\n--- [bold]{briefing_result.title}: {active_project.project_name}[/bold] ---\n"
        )
        console.print(
            Markdown(briefing_result.briefing_text or "No briefing generated.")
        )
