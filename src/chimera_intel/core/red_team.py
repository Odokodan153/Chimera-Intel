"""
Red Team Module for Chimera Intel.

This module uses AI to analyze aggregated OSINT data from a red team
perspective, generating potential attack vectors and actionable TTPs.

!! WARNING !!
This module is for authorized security professionals only.
All actions require an explicit, signed consent file (Rules of Engagement)
and are logged to an audit trail.
"""

import typer
import json
import yaml
import os
from typing import Optional, Dict, Any, List

from .database import get_aggregated_data_for_target, get_data_by_module
from .ai_core import generate_ai_analysis
from .config_loader import API_KEYS
from .utils import console
from .security_utils import (
    audit_event,
    load_consent,
    check_consent_for_action,
    normalize_ai_result,
    redact_personal_data,
    _first_n
)

red_team_app = typer.Typer(
    name="red-team",
    help="Generates red team insights. REQUIRES --consent.",
)


def generate_attack_vectors(
    target: str, 
    consent: dict,
    dry_run: bool = True,
    ai_call=generate_ai_analysis, 
    db_get=get_aggregated_data_for_target, 
    api_key_get=lambda: API_KEYS.get("google_api_key")
) -> Optional[Dict[str, Any]]:
    """
    Analyzes aggregated OSINT data to generate potential attack vectors.
    """
    console.print(
        f"[bold cyan]Generating potential attack vectors for {target}...[/bold cyan]"
    )

    api_key = api_key_get()
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        raise typer.Exit(code=1)
        
    aggregated_data = db_get(target)
    if not aggregated_data:
        return None
        
    # Redact data BEFORE sending to AI
    safe_data = redact_personal_data(str(aggregated_data))

    prompt = f"""
    As a red team operator, analyze the following aggregated OSINT data for the target: {target}.
    Your objective is to identify the most likely and impactful attack vectors.
    Based on the data, generate a report that includes:
    1.  **Top 3 Attack Vectors:** Describe three specific, plausible attack vectors.
    2.  **Recommended TTPs:** For each vector, suggest relevant MITRE ATT&CK techniques (TTPs) that could be used.
    3.  **Required Information Gaps:** What critical information is missing that would be needed to execute these attacks?

    **Aggregated (Sanitized) OSINT Data:**
    {safe_data}
    """

    ai_result = ai_call(prompt, api_key)
    error, text = normalize_ai_result(ai_result)

    if error:
        console.print(f"[bold red]AI Analysis Error:[/bold red] {error}")
        return None
        
    # Redact output from AI as a precaution
    safe_text = redact_personal_data(text)
    
    if dry_run:
        console.print("[yellow]Dry-run mode: Analysis generated but not saved.[/yellow]")
        
    return {"red_team_analysis": safe_text}


@red_team_app.command("generate")
def run_red_team_analysis(
    target: str = typer.Argument(
        ..., help="The target entity (e.g., a domain or company name)."
    ),
    consent_file: str = typer.Option(
        ..., "--consent", help="Path to signed consent (YAML/JSON) file (Rules of Engagement)."
    ),
    dry_run: bool = typer.Option(
        True, "--dry-run/--no-dry-run", help="Run in dry-run mode without saving outputs."
    ),
    user: str = typer.Option(
        os.getenv("USER", "unknown"), help="User ID for audit logging."
    ),
):
    """
    Performs a red team analysis on the aggregated data for a target.
    Requires a valid consent file authorizing the 'ttp_analysis' action.
    """
    action_name = "ttp_analysis"
    
    try:
        consent = load_consent(consent_file)
    except Exception as e:
        console.print(f"[bold red]Consent load error:[/bold red] {e}")
        raise typer.Exit(code=1)

    if not check_consent_for_action(consent, target, action_name):
        console.print(f"[bold red]Authorization Denied:[/bold red] This consent file does not authorize the action '{action_name}' for target '{target}'.")
        raise typer.Exit(code=1)

    audit_event(user=user, action=action_name, target=target, consent_id=consent.get("id"), note="Dry-run: {dry_run}")

    if dry_run:
        console.print("[yellow]Running in DRY-RUN mode. No files will be created.[/yellow]")

    try:
        result = generate_attack_vectors(target, consent=consent, dry_run=dry_run)
    except typer.Exit:
        raise # Propagate exits from the core function
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Unexpected error: {e}")
        audit_event(user=user, action=f"{action_name}_failed", target=target, consent_id=consent.get("id"), note=str(e))
        raise typer.Exit(code=1)
        
    if result:
        console.print(f"\n[bold green]Red Team Analysis for {target}:[/bold green]")
        console.print(result["red_team_analysis"])
    else:
        console.print(f"No data found for target '{target}'")


# --- Phishing Simulation Functionality ---

def generate_phishing_simulation(
    target: str, 
    consent: dict,
    dry_run: bool = True,
    ai_call=generate_ai_analysis, 
    db_get=get_data_by_module, 
    api_key_get=lambda: API_KEYS.get("google_api_key")
) -> Optional[Dict[str, Any]]:
    """
    Generates a phishing simulation template based on gathered OSINT.
    (This is the secure, DI-ready function from your assessment)
    """
    console.print(f"[cyan]Generating phishing simulation for {target}...[/cyan]")

    api_key = api_key_get()
    if not api_key:
        console.print("[red]Missing API key.[/red]")
        raise typer.Exit(code=1)

    personnel_data = db_get(target, "personnel_osint")
    content_data = db_get(target, "offensive_enum_content")

    if not personnel_data and not content_data:
        console.print(f"No OSINT data (personnel, content) found for target '{target}'.")
        return None

    # Redact data BEFORE sending to AI
    sample_personnel = redact_personal_data(str(_first_n(personnel_data, 5)))
    sample_content = redact_personal_data(str(_first_n(content_data, 5)))

    prompt = f"""
    As a security awareness auditor (for testing only), design a phishing simulation template for '{target}'.
    Use sanitized OSINT data below (PII redacted):

    Personnel: {sample_personnel}
    Content: {sample_content}
    
    Task:
    Generate a complete phishing simulation with the following components:
    1.  **Sender Name:** A plausible sender (e.g., "IT Support", "HR Department").
    2.  **Email Subject:** A compelling, urgent subject line.
    3.  **Email Body:** The full text of the email.
    4.  **Lure/Hook:** Explain the psychological trick used.
    
    Format the output clearly.
    """

    ai_result = ai_call(prompt, api_key)
    error, text = normalize_ai_result(ai_result)
    
    if error:
        console.print(f"[red]AI Error:[/red] {error}")
        return None

    # Redact output from AI as a precaution
    text = redact_personal_data(text)

    if dry_run:
        console.print("[yellow]Dry-run mode: Template generated but not saved.[/yellow]")

    return {"phishing_simulation_template": text}

@red_team_app.command("phishing-simulation")
def run_phishing_simulation(
    target: str = typer.Argument(
        ..., help="The target entity to design a simulation for."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save simulation template to a file (e.g., 'phish.txt')."
    ),
    consent_file: str = typer.Option(
        ..., "--consent", help="Path to signed consent (YAML/JSON) file (Rules of Engagement)."
    ),
    dry_run: bool = typer.Option(
        True, "--dry-run/--no-dry-run", help="Run in dry-run mode without saving outputs."
    ),
    user: str = typer.Option(
        os.getenv("USER", "unknown"), help="User ID for audit logging."
    ),
):
    """
    Generates a phishing simulation based on gathered personnel and web OSINT.
    Requires a valid consent file authorizing the 'phishing' action.
    """
    action_name = "phishing"

    try:
        consent = load_consent(consent_file)
    except Exception as e:
        console.print(f"[bold red]Consent load error:[/bold red] {e}")
        raise typer.Exit(code=1)

    if not check_consent_for_action(consent, target, action_name):
        console.print(f"[bold red]Authorization Denied:[/bold red] This consent file does not authorize the action '{action_name}' for target '{target}'.")
        raise typer.Exit(code=1)

    audit_event(user=user, action=f"{action_name}_simulation_requested", target=target, consent_id=consent.get("id"), note=f"Dry-run: {dry_run}")
    
    if dry_run:
        console.print("[yellow]Running in DRY-RUN mode. No files will be created.[/yellow]")
    
    try:
        result = generate_phishing_simulation(target, consent=consent, dry_run=dry_run)
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Unexpected error: {e}")
        audit_event(user=user, action=f"{action_name}_simulation_failed", target=target, consent_id=consent.get("id"), note=str(e))
        raise typer.Exit(code=1)
        
    if result:
        analysis_text = result["phishing_simulation_template"]
        console.print(f"\n[bold green]Phishing Simulation Template for {target}:[/bold green]")
        console.print(analysis_text)
        
        if output_file and not dry_run:
            try:
                # TODO: Add path validation here to restrict writes to a known directory
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(analysis_text)
                console.print(f"\n[bold green]Simulation template saved to {output_file}[/bold green]")
                audit_event(user=user, action=f"{action_name}_template_saved", target=target, consent_id=consent.get("id"), note=f"File: {output_file}")
            except Exception as e:
                console.print(f"\n[bold red]Error saving file:[/bold red] {e}")
    else:
        console.print(f"No OSINT data found for target '{target}' to generate simulation.")

# --- Adversary Emulation Functionality ---

def _export_ttp_to_atomic(ttp_id: str, plan_text: str) -> str:
    """Converts an AI-generated plan to Atomic Red Team (YAML) format."""
    console.print(f"[bold cyan]Converting plan for {ttp_id} to Atomic Red Team (YAML) format...[/bold cyan]")
    
    atomic_dict = {
        "attack_technique": ttp_id,
        "display_name": f"AI-Generated Emulation for {ttp_id}",
        "atomic_tests": [
            {
                "name": f"AI-Generated Plan for {ttp_id}",
                "description": plan_text,
                "supported_platforms": ["windows", "linux", "macos"],
                "executor": {
                    "name": "manual",
                    "command": (
                        "# This plan is designed for manual review and execution.\n"
                        "# See 'Detection & Analytics' for blue team monitoring points."
                    )
                }
            }
        ]
    }
    
    return yaml.dump(atomic_dict, sort_keys=False)

def simulate_adversary_ttp(
    target: str, 
    ttp_id: str, 
    consent: dict,
    dry_run: bool = True,
    ai_call=generate_ai_analysis, 
    db_get=get_aggregated_data_for_target, 
    api_key_get=lambda: API_KEYS.get("google_api_key")
) -> Optional[Dict[str, Any]]:
    """
    Generates an adversary emulation plan for a specific TTP.
    """
    console.print(
        f"[bold cyan]Generating emulation plan for TTP {ttp_id} against {target}...[/bold cyan]"
    )
    
    api_key = api_key_get()
    if not api_key:
        console.print("[bold red]Error:[/bold red] Google API key not configured.")
        raise typer.Exit(code=1)

    aggregated_data = db_get(target)
    if not aggregated_data:
        return None # No data to work with
        
    # Redact data BEFORE sending to AI
    safe_data = redact_personal_data(str(aggregated_data)[:2000]) # Truncate for prompt

    prompt = f"""
    As a senior purple team operator, design an adversary emulation plan
    for the target '{target}' based on the following MITRE ATT&CK TTP: {ttp_id}.

    Use the provided sanitized OSINT data to make the simulation steps realistic.

    **Sanitized OSINT Data (sample):**
    {safe_data} 

    **Task:**
    Generate a complete simulation plan with the following components:
    1.  **TTP Objective:** Briefly explain what this TTP achieves.
    2.  **Emulation Steps (Red Team):** Provide 3-5 specific, actionable steps.
    3.  **Detection & Analytics (Blue Team):** For each step, describe a specific detection analytic.
    4.  **Mitigation (Blue Team):** Recommend a primary mitigation for this TTP.
    
    Format the output clearly with markdown.
    """

    ai_result = ai_call(prompt, api_key)
    error, text = normalize_ai_result(ai_result)

    if error:
        console.print(f"[bold red]AI Analysis Error:[/bold red] {error}")
        return None
    
    # Redact output from AI as a precaution
    safe_text = redact_personal_data(text)

    if dry_run:
        console.print("[yellow]Dry-run mode: TTP plan generated but not saved.[/yellow]")
        
    return {"ttp_simulation_plan": safe_text}

@red_team_app.command("simulate-ttp")
def run_ttp_simulation(
    target: str = typer.Argument(
        ..., help="The target entity to simulate against."
    ),
    ttp_id: str = typer.Argument(
        ..., help="The MITRE ATT&CK TTP ID (e.g., 'T1566', 'T1059.001')."
    ),
    export: Optional[str] = typer.Option(
        None, "--export", help="Export plan to a file in a specific format (e.g., 'json', 'atomic')."
    ),
    consent_file: str = typer.Option(
        ..., "--consent", help="Path to signed consent (YAML/JSON) file (Rules of Engagement)."
    ),
    dry_run: bool = typer.Option(
        True, "--dry-run/--no-dry-run", help="Run in dry-run mode without saving outputs."
    ),
    user: str = typer.Option(
        os.getenv("USER", "unknown"), help="User ID for audit logging."
    ),
):
    """
    Generates an adversary emulation plan for a specific TTP.
    Requires a valid consent file authorizing the 'ttp' action.
    """
    action_name = "ttp" # Short for TTP simulation
    
    try:
        consent = load_consent(consent_file)
    except Exception as e:
        console.print(f"[bold red]Consent load error:[/bold red] {e}")
        raise typer.Exit(code=1)

    if not check_consent_for_action(consent, target, action_name):
        console.print(f"[bold red]Authorization Denied:[/bold red] This consent file does not authorize the action '{action_name}' for target '{target}'.")
        raise typer.Exit(code=1)

    audit_event(user=user, action=f"{action_name}_simulation_requested", target=target, consent_id=consent.get("id"), note=f"TTP: {ttp_id}, Dry-run: {dry_run}")

    if dry_run:
        console.print("[yellow]Running in DRY-RUN mode. No files will be created.[/yellow]")
        
    try:
        result = simulate_adversary_ttp(target, ttp_id, consent=consent, dry_run=dry_run)
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Unexpected error: {e}")
        audit_event(user=user, action=f"{action_name}_simulation_failed", target=target, consent_id=consent.get("id"), note=str(e))
        raise typer.Exit(code=1)
        
    if result:
        plan_text = result["ttp_simulation_plan"]
        console.print(f"\n[bold green]TTP Emulation Plan for {target} ({ttp_id}):[/bold green]")
        console.print(plan_text)

        if export and not dry_run:
            output_data = ""
            file_extension = ""
            
            if export.lower() == "json":
                output_data = json.dumps(result, indent=2)
                file_extension = ".json"
            elif export.lower() == "atomic":
                output_data = _export_ttp_to_atomic(ttp_id, plan_text)
                file_extension = ".yaml"
            else:
                console.print(f"[bold red]Error:[/bold red] Unknown export format '{export}'. Supported: 'json', 'atomic'.")
                raise typer.Exit(code=1)
                
            output_file = f"ttp_plan_{target.replace('.', '_')}_{ttp_id.replace('.', '_')}{file_extension}"
            try:
                # TODO: Add path validation here to restrict writes to a known directory
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(output_data)
                console.print(f"\n[bold green]TTP Emulation Plan exported to {output_file}[/bold green]")
                audit_event(user=user, action=f"{action_name}_plan_saved", target=target, consent_id=consent.get("id"), note=f"File: {output_file}")
            except Exception as e:
                console.print(f"\n[bold red]Error saving file:[/bold red] {e}")
        elif export and dry_run:
            console.print(f"[yellow]Would export to {export} format, but dry-run is enabled.[/yellow]")
            
    else:
        console.print(f"No OSINT data found for target '{target}' to generate simulation plan.")