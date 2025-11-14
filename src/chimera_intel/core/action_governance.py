"""
Module for Action Governance and Risk Scoring.

This module provides a framework for classifying all CLI actions within Chimera
into risk categories (e.g., Passive, Aggressive, Disallowed) and running
automated pre-flight checks for legal and compliance constraints.

This integrates concepts from:
- legint.py (for sanctions/compliance checks)
- security_utils.py (for consent-gated actions, as seen in red_team.py)
"""

import typer
import logging
from typing import Dict, Optional
from .schemas import ActionMetadata, ActionRiskLevel
from .legint import screen_for_sanctions
from .security_utils import load_consent, check_consent_for_action
from .utils import console

logger = logging.getLogger(__name__)


ACTION_REGISTRY: Dict[str, ActionMetadata] = {
    "recon:domain-scan": ActionMetadata(
        description="Performs OSINT on a domain.",
        risk_level=ActionRiskLevel.BENIGN_INTERACTION,
    ),
    "legint:sanctions-screener": ActionMetadata(
        description="Checks an entity against public sanctions lists.",
        risk_level=ActionRiskLevel.BENIGN_INTERACTION,
    ),
    "red-team:generate": ActionMetadata(
        description="Generates potential attack vectors based on data.",
        risk_level=ActionRiskLevel.AGGRESSIVE,
        legal_metadata="Requires explicit, signed consent (Rules of Engagement).",
        consent_required=True,
    ),
    "red-team:phishing-simulation": ActionMetadata(
        description="Generates a phishing simulation template.",
        risk_level=ActionRiskLevel.AGGRESSIVE,
        legal_metadata="Requires explicit, signed consent (Rules of Engagement).",
        consent_required=True,
    ),
    "example:disallowed": ActionMetadata(
        description="An example of an action that is always disallowed.",
        risk_level=ActionRiskLevel.DISALLOWED,
        legal_metadata="This action is prohibited under local law.",
    ),
}


def run_pre_flight_checks(
    action_name: str,
    target: str,
    consent_file: Optional[str] = None
) -> bool:
    """
    Runs all legal and compliance pre-flight checks for a given action.
    Returns True if the action is allowed, False otherwise.
    """
    console.print(f"[bold cyan]Running pre-flight checks for '{action_name}' on target '{target}'...[/bold cyan]")
    
    # 1. Check Action Risk Classification
    metadata = ACTION_REGISTRY.get(action_name)
    if not metadata:
        console.print(f"[yellow]Warning:[/yellow] No governance metadata found for '{action_name}'. Allowing by default.")
        return True

    console.print(f"  - Action Risk Level: {metadata.risk_level.value}")

    if metadata.risk_level == ActionRiskLevel.DISALLOWED:
        console.print(f"[bold red]ACTION BLOCKED:[/bold red] This action is classified as 'Disallowed'.")
        console.print(f"  - Legal Note: {metadata.legal_metadata}")
        return False

    # 2. Check Consent
    if metadata.consent_required:
        if not consent_file:
            console.print(f"[bold red]ACTION BLOCKED:[/bold red] This action requires a '--consent' file.")
            return False
        try:
            consent = load_consent(consent_file)
            if not check_consent_for_action(consent, target, action_name.split(":")[-1]):
                console.print(f"[bold red]ACTION BLOCKED:[/bold red] Consent file does not authorize this action for this target.")
                return False
            console.print("  - [green]Consent check: PASSED[/green]")
        except Exception as e:
            console.print(f"[bold red]Consent Error:[/bold red] {e}")
            return False

    # 3. Check Compliance (e.g., Sanctions)
    # This is an example pre-check. More can be added.
    try:
        sanctions_result = screen_for_sanctions(target)
        if sanctions_result.hits_found > 0:
            console.print(f"[bold red]ACTION BLOCKED:[/bold red] Target '{target}' is on a sanctions list.")
            for entity in sanctions_result.entities:
                console.print(f"  - Found: {entity.name} (Lists: {', '.join(entity.programs)})")
            return False
        console.print("  - [green]Sanctions check: PASSED[/green]")
    except Exception as e:
        console.print(f"[bold red]Compliance Check Failed:[/bold red] {e}")
        return False

    console.print("[bold green]All pre-flight checks passed. Action is authorized.[/bold green]")
    return True


# --- Typer CLI Application ---

gov_app = typer.Typer(
    name="governance",
    help="Tools for managing action governance and risk policies.",
)

@gov_app.command("check")
def cli_check_action(
    action_name: str = typer.Argument(..., help="The action name (e.g., 'red-team:generate')."),
    target: str = typer.Argument(..., help="The target entity for the action."),
    consent_file: Optional[str] = typer.Option(
        None, "--consent", help="Path to signed consent file (if required)."
    ),
):
    """
    Performs a dry-run pre-flight check for an action against a target.
    """
    if not run_pre_flight_checks(action_name, target, consent_file):
        raise typer.Exit(code=1)
    else:
        console.print("\nAction would be allowed.")


@gov_app.command("list")
def cli_list_actions():
    """Lists all registered actions and their risk levels."""
    for action, meta in ACTION_REGISTRY.items():
        console.print(f"- [bold]{action}[/bold] ({meta.risk_level.value}): {meta.description}")