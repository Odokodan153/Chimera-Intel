"""
Red Team Module for Chimera Intel.

This module uses AI to analyze aggregated OSINT data from a red team
perspective, generating potential attack vectors and actionable TTPs.
"""

import typer
from typing import Optional, Dict, Any

from .database import get_aggregated_data_for_target
from .ai_core import generate_swot_from_data
from .config_loader import API_KEYS
from .utils import console

red_team_app = typer.Typer(
    name="red-team",
    help="Generates red team insights and potential attack vectors.",
)


def generate_attack_vectors(target: str) -> Optional[Dict[str, Any]]:
    """
    Analyzes aggregated OSINT data to generate potential attack vectors.
    Returns a dict with results on success, raises typer.Exit(code=1) for unrecoverable errors.
    """
    console.print(
        f"[bold cyan]Generating potential attack vectors for {target}...[/bold cyan]"
    )

    api_key = API_KEYS.google_api_key
    if not api_key:
        # Make this an explicit CLI error so tests expecting exit code 1 get it.

        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        raise typer.Exit(code=1)
    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data:
        # No data is not an error for the CLI; handle in the caller (so tests can assert text).

        return None
    prompt = f"""
    As a red team operator, analyze the following aggregated OSINT data for the target: {target}.
    Your objective is to identify the most likely and impactful attack vectors.
    Based on the data, generate a report that includes:
    1.  **Top 3 Attack Vectors:** Describe three specific, plausible attack vectors.
    2.  **Recommended TTPs:** For each vector, suggest relevant MITRE ATT&CK techniques (TTPs) that could be used.
    3.  **Required Information Gaps:** What critical information is missing that would be needed to execute these attacks?

    **Aggregated OSINT Data:**
    {aggregated_data}
    """

    ai_result = generate_swot_from_data(prompt, api_key)

    if ai_result.error:
        console.print(f"[bold red]AI Analysis Error:[/bold red] {ai_result.error}")
        return None
    return {"red_team_analysis": ai_result.analysis_text}


@red_team_app.command("generate")
def run_red_team_analysis(
    target: str = typer.Argument(
        ..., help="The target entity (e.g., a domain or company name)."
    )
):
    """
    Performs a red team analysis on the aggregated data for a target.
    """
    try:
        result = generate_attack_vectors(target)
    except typer.Exit as te:
        # Re-raise Typer exits so Typer handles the exit code (this preserves the exit code).

        raise te
    except Exception as e:
        # Unexpected internal error -> return non-zero exit (1) and print message.

        console.print(f"[bold red]Error:[/bold red] Unexpected error: {e}")
        raise typer.Exit(code=1)
    if result:
        console.print(f"\n[bold green]Red Team Analysis for {target}:[/bold green]")
        console.print(result["red_team_analysis"])
    else:
        # No data found for the target — this is a normal but noteworthy outcome.

        console.print(f"No data found for target '{target}'")
