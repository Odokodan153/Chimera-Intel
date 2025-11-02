"""
Red Team Module for Chimera Intel.

This module uses AI to analyze aggregated OSINT data from a red team
perspective, generating potential attack vectors and actionable TTPs.
"""

import typer
from typing import Optional, Dict, Any, List

from .database import get_aggregated_data_for_target, get_data_by_module
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


# --- New Phishing Simulation Functionality ---

def generate_phishing_simulation(target: str) -> Optional[Dict[str, Any]]:
    """
    Generates a phishing simulation template based on gathered OSINT.
    """
    console.print(
        f"[bold cyan]Generating phishing simulation for {target}...[/bold cyan]"
    )
    
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        raise typer.Exit(code=1)

    # 1. Gather relevant data
    try:
        # Get personnel names/emails (assuming a 'personnel_osint' module exists)
        personnel_data = get_data_by_module(target, "personnel_osint")
        # Get discovered web content (from 'offensive_enum_content')
        content_data = get_data_by_module(target, "offensive_enum_content")
    except Exception as e:
        console.print(f"[bold red]Database Error:[/bold red] Could not fetch OSINT data: {e}")
        return None

    if not personnel_data and not content_data:
        return None # No data to work with

    # 2. Build the AI prompt
    prompt = f"""
    As a security awareness auditor, design a realistic phishing simulation template
    targeting employees of '{target}'.
    
    Use the following OSINT data to make the phish highly customized and plausible:
    
    **Known Personnel Data (sample):**
    {personnel_data[:5]} 
    
    **Discovered Web Content (e.g., login portals, internal sites):**
    {content_data[:5]}

    **Task:**
    Generate a complete phishing simulation with the following components:
    1.  **Sender Name:** A plausible sender (e.g., "IT Support", "HR Department").
    2.  **Email Subject:** A compelling, urgent subject line.
    3.  **Email Body:** The full text of the email. It should be professional,
        reference one or more pieces of the OSINT data (e.g., a known login portal),
        and create a sense of urgency to click a link.
    4.  **Lure/Hook:** Explain the psychological trick used (e.g., "Urgent action required," "Password expiry").
    
    Format the output clearly.
    """

    # 3. Call the AI
    ai_result = generate_swot_from_data(prompt, api_key)

    if ai_result.error:
        console.print(f"[bold red]AI Analysis Error:[/bold red] {ai_result.error}")
        return None
        
    return {"phishing_simulation_template": ai_result.analysis_text}

@red_team_app.command("phishing-simulation")
def run_phishing_simulation(
    target: str = typer.Argument(
        ..., help="The target entity to design a simulation for."
    )
):
    """
    Generates a phishing simulation based on gathered personnel and web OSINT.
    """
    try:
        result = generate_phishing_simulation(target)
    except typer.Exit as te:
        raise te
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Unexpected error: {e}")
        raise typer.Exit(code=1)
        
    if result:
        console.print(f"\n[bold green]Phishing Simulation Template for {target}:[/bold green]")
        console.print(result["phishing_simulation_template"])
    else:
        console.print(f"No OSINT data found for target '{target}' to generate simulation.")