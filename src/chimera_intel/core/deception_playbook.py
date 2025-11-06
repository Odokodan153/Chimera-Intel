"""
Orchestration module for the full Deception Incident Response (IR) Playbook.

This module implements the 6-step playbook by calling and coordinating other
core modules:
1.  Triage:   (Uses image_forensics_pipeline)
2.  Contain:  (Uses response.ACTION_MAP['platform_takedown_request'])
3.  Notify:   (Uses response.ACTION_MAP['internal_threat_warning'])
4.  Public:   (Uses response.ACTION_MAP['generate_debunking_script'])
5.  Preserve: (Uses forensic_vault)
6.  Mitigate: (New function)
"""

import typer
import logging
import pathlib
import json
from typing import Optional, Dict, Any, List
from rich.console import Console
from typer.testing import CliRunner

# --- Reuse existing modules ---
from .utils import save_or_print_results
from .schemas import BaseAnalysisResult

# Step 1: Triage
# Import the Typer app from the pipeline module to call it via CliRunner
from .image_forensics_pipeline import pipeline_app as forensics_app

# Step 2, 3, 4: Contain, Notify, Public Response
# Import the ACTION_MAP to get the real functions
from .response import ACTION_MAP as response_action_map

# Step 5: Forensic Preservation
# Import the Typer app from the vault module
from .forensic_vault import vault_app

logger = logging.getLogger(__name__)
console = Console()
playbook_app = typer.Typer(
    name="playbook",
    help="Run automated IR playbooks for specific threats.",
)

# --- Define Pydantic Model for Playbook Report ---
class PlaybookStepResult(BaseAnalysisResult):
    """Holds the result of a single playbook step."""
    step_name: str
    success: bool
    details: str
    output_files: Optional[List[str]] = None

class DeceptionPlaybookReport(BaseAnalysisResult):
    """Final report for the deception playbook."""
    media_file: str
    target_executive: str
    forensic_key_file: str
    steps: List[PlaybookStepResult] = []


# --- Playbook Step Implementations ---

def _step_1_triage(
    media_path: pathlib.Path, runner: CliRunner
) -> PlaybookStepResult:
    """
    Step 1: Triage
    Confirm authenticity using the full forensic pipeline.
    """
    console.print("[bold cyan]Running Step 1: Triage (Forensic Pipeline)...[/bold cyan]")
    output_json = f"{media_path.stem}_forensics_report.json"
    
    # We use CliRunner to execute the existing Typer command,
    # capturing its output. This is a "real" call.
    result = runner.invoke(
        forensics_app,
        ["run", str(media_path), "--output", output_json],
        catch_exceptions=False
    )
    
    success = result.exit_code == 0
    details = f"Forensic pipeline executed. See report: {output_json}"
    if not success:
        details = f"Forensic pipeline failed: {result.stdout}"
        
    return PlaybookStepResult(
        step_name="Triage",
        success=success,
        details=details,
        output_files=[output_json] if success else None
    )

def _step_2_contain(
    event_details: Dict[str, Any]
) -> PlaybookStepResult:
    """
    Step 2: Contain
    Request takedown via platform abuse channels.
    """
    console.print("[bold cyan]Running Step 2: Contain (Platform Takedown)...[/bold cyan]")
    try:
        # Get the real function from the imported map
        takedown_func = response_action_map.get("platform_takedown_request")
        if not takedown_func:
            return PlaybookStepResult(
                step_name="Contain", success=False, details="Action 'platform_takedown_request' not found in ACTION_MAP."
            )
        
        # Call the action function directly
        takedown_func(event_details)
        
        return PlaybookStepResult(
            step_name="Contain",
            success=True,
            details="Takedown requests submitted (simulated POSTs to X/Meta)."
        )
    except Exception as e:
        return PlaybookStepResult(step_name="Contain", success=False, details=str(e))

def _step_3_notify(
    event_details: Dict[str, Any]
) -> PlaybookStepResult:
    """
    Step 3: Attribution & Notification
    Notify legal/comms teams.
    """
    console.print("[bold cyan]Running Step 3: Notify (Internal Alert)...[/bold cyan]")
    try:
        notify_func = response_action_map.get("internal_threat_warning")
        if not notify_func:
            return PlaybookStepResult(
                step_name="Notify", success=False, details="Action 'internal_threat_warning' not found in ACTION_MAP."
            )
        
        notify_func(event_details)
        return PlaybookStepResult(
            step_name="Notify",
            success=True,
            details="Internal high-priority alert sent via webhook (Slack)."
        )
    except Exception as e:
        return PlaybookStepResult(step_name="Notify", success=False, details=str(e))

def _step_4_public_response(
    event_details: Dict[str, Any]
) -> PlaybookStepResult:
    """
    Step 4: Public Response
    Prepare verified official content and a statement.
    """
    console.print("[bold cyan]Running Step 4: Public Response (Draft Debunk)...[/bold cyan]")
    try:
        debunk_func = response_action_map.get("generate_debunking_script")
        if not debunk_func:
            return PlaybookStepResult(
                step_name="Public Response", success=False, details="Action 'generate_debunking_script' not found in ACTION_MAP."
            )

        debunk_func(event_details)
        # Find the generated file (this is fragile, but based on response.py)
        draft_file = [f for f in pathlib.Path(".").glob("debunking_draft_*.txt")][-1]
        
        return PlaybookStepResult(
            step_name="Public Response",
            success=True,
            details=f"Debunking script draft generated.",
            output_files=[str(draft_file)]
        )
    except Exception as e:
        return PlaybookStepResult(step_name="Public Response", success=False, details=str(e))

def _step_5_preserve(
    media_path: pathlib.Path, key_path: pathlib.Path, runner: CliRunner
) -> PlaybookStepResult:
    """
    Step 5: Forensic Preservation
    Capture evidence into the vault.
    """
    console.print("[bold cyan]Running Step 5: Preserve (Forensic Vault)...[/bold cyan]")
    output_receipt = f"{media_path.stem}_receipt.json"

    result = runner.invoke(
        vault_app,
        [
            "create-receipt",
            str(media_path),
            "--key", str(key_path),
            "--output", output_receipt,
        ],
        catch_exceptions=False
    )
    
    success = result.exit_code == 0
    details = f"Evidence receipt created: {output_receipt}"
    if not success:
        details = f"Vault receipt creation failed: {result.stdout}"

    return PlaybookStepResult(
        step_name="Preserve",
        success=success,
        details=details,
        output_files=[output_receipt] if success else None
    )

def _step_6_mitigate(
    event_details: Dict[str, Any]
) -> PlaybookStepResult:
    """
    Step 6: Mitigation
    Prepare mitigation brief.
    """
    console.print("[bold cyan]Running Step 6: Mitigate (Action Plan)...[/bold cyan]")
    target = event_details.get("target", "the executive")
    
    template = f"""
    [MITIGATION ACTION PLAN - DRAFT]
    
    INCIDENT: High-confidence deepfake targeting {target}.
    
    IMMEDIATE ACTIONS:
    1.  [Partner Comms] Notify key partners (via secure channels) to be 
        wary of any unusual requests from {target}.
    2.  [Internal FAQ] Update internal employee FAQ with a brief, non-public
        note about a "malicious impersonation attempt".
    3.  [C-C-V] Accelerate adoption of "Call-Confirm-Verify" protocols for
        all financial or sensitive data requests.
        
    LONG-TERM ACTIONS:
    1.  [Verified Credentials] Review plan to adopt C2PA/AMBER 
        (or other verified media credential) for all official executive 
        communications.
    2.  [Training] Add this incident as a case study for new-hire and 
        executive security awareness training.
    """
    
    filename = f"mitigation_plan_{target.replace(' ', '_')}.txt"
    try:
        with open(filename, "w") as f:
            f.write(template)
        return PlaybookStepResult(
            step_name="Mitigate",
            success=True,
            details=f"Mitigation plan draft saved to '{filename}'.",
            output_files=[filename]
        )
    except Exception as e:
        return PlaybookStepResult(step_name="Mitigate", success=False, details=str(e))


# --- Main Playbook Orchestrator ---

@playbook_app.command("run-deception")
def run_deception_playbook(
    media_file: pathlib.Path = typer.Argument(
        ..., exists=True, help="Path to the suspected deepfake media file."
    ),
    target_executive: str = typer.Option(
        ..., "--target", "-t", help="Name of the executive being impersonated."
    ),
    key_file: pathlib.Path = typer.Option(
        ..., "--key", "-k", exists=True, help="Path to the private key (.pem) for signing vault receipts."
    ),
    output_file: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Save final playbook report to a JSON file."
    ),
):
    """
    Runs the full 6-step incident response playbook for a deepfake.
    """
    console.print(f"[bold]>>> LAUNCHING DECEPTION PLAYBOOK for {target_executive} <<<[/bold]")
    
    report = DeceptionPlaybookReport(
        media_file=str(media_file),
        target_executive=target_executive,
        forensic_key_file=str(key_file)
    )
    
    cli_runner = CliRunner()
    
    # This `event_details` dict is used by all response actions
    event_details = {
        "media_file": str(media_file),
        "target": target_executive,
        "confidence": "High (Playbook Triggered)",
        "incident_type": "deception_playbook"
    }

    # Execute all 6 steps in order
    
    # Step 1: Triage
    step1_res = _step_1_triage(media_file, cli_runner)
    report.steps.append(step1_res)
    if not step1_res.success:
        console.print("[bold red]Triage failed. Aborting playbook.[/bold red]")
        typer.Exit(code=1)
    
    # Step 2: Contain
    step2_res = _step_2_contain(event_details)
    report.steps.append(step2_res)
    
    # Step 3: Notify
    step3_res = _step_3_notify(event_details)
    report.steps.append(step3_res)
    
    # Step 4: Public Response
    step4_res = _step_4_public_response(event_details)
    report.steps.append(step4_res)
    
    # Step 5: Preserve
    step5_res = _step_5_preserve(media_file, key_file, cli_runner)
    report.steps.append(step5_res)
    
    # Step 6: Mitigate
    step6_res = _step_6_mitigate(event_details)
    report.steps.append(step6_res)
    
    console.print("[bold green]>>> PLAYBOOK COMPLETE <<<[/bold green]")
    
    report.success = all(s.success for s in report.steps)
    if not report.success:
        console.print("[bold yellow]Warning: One or more playbook steps failed.[/bold yellow]")

    # Save final report
    results_dict = report.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)


if __name__ == "__main__":
    playbook_app()