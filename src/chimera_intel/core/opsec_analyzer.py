"""
Module for Operational Security (OPSEC) Analysis.

Correlates data from multiple scans to find potential OPSEC weaknesses, such as
developers using compromised credentials.
"""

import typer
import logging
from typing import Optional, List, Set, Dict, Any
from typing_extensions import Annotated # Import Annotated

# --- Existing Imports ---
from .schemas import OpsecReport, CompromisedCommitter
from .utils import save_or_print_results
from .database import get_aggregated_data_for_target, save_scan_to_db
from .project_manager import resolve_target

# --- NEW IMPORTS for OpsecFootprint ---
from .opsec_footprint import OpsecFootprint
from .schemas import Organization
# --- End New Imports ---

logger = logging.getLogger(__name__)


def generate_opsec_report(target: str) -> OpsecReport:
    """
    Generates an OPSEC report by correlating data from various modules.
    """
    logger.info(f"Generating OPSEC report for {target}")
    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data:
        return OpsecReport(target=target, error="No historical data found for target.")
    modules = aggregated_data.get("modules", {})
    compromised_committers: List[CompromisedCommitter] = []

    # --- Feature 1: Developer OPSEC Audit ---

    committer_emails: Set[str] = set()
    code_intel_data = modules.get("code_intel_repo", {}).get("top_committers", [])
    for committer in code_intel_data:
        committer_emails.add(committer.get("email", "").lower())
    breach_data = modules.get("defensive_breaches", {}).get("breaches", [])
    if committer_emails and breach_data:
        # Create a mapping from breached emails to breach names for efficient lookup

        breached_email_map: Dict[str, Set[str]] = {}
        for breach in breach_data:
            breach_name = breach.get("Name")
            if not breach_name:
                continue
            for email in breach.get("DataClasses", []):
                lower_email = email.lower()
                if "@" in lower_email:
                    if lower_email not in breached_email_map:
                        breached_email_map[lower_email] = set()
                    breached_email_map[lower_email].add(breach_name)
        for email in committer_emails:
            if email in breached_email_map:
                compromised_committers.append(
                    CompromisedCommitter(
                        email=email,
                        source_repository=modules.get("code_intel_repo", {}).get(
                            "repository_url"
                        ),
                        related_breaches=list(breached_email_map[email]),
                    )
                )
    return OpsecReport(target=target, compromised_committers=compromised_committers)


# This is the app your plugin imports
opsec_app = typer.Typer()


@opsec_app.command("run")
def run_opsec_analysis(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="The target to analyze. Uses active project."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Correlates scan data to find operational security (OPSEC) weaknesses.
    """
    try:
        target_name = resolve_target(target, required_assets=["company_name", "domain"])
        results_model = generate_opsec_report(target_name)
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(target=target_name, module="opsec_report", data=results_dict)
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)

# ---
# --- NEW 'footprint' Command ---
# ---
@opsec_app.command("footprint")
def run_opsec_footprint(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target company name. Uses active project if None."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save report summary to JSON."
    ),
):
    """
    Generates a proactive Adversary Risk Exposure Report.
    """
    try:
        target_name = resolve_target(target, required_assets=["company_name", "domain"])
        
        # Fetch organization details from project
        # This is a stub, replace with your actual project logic
        # e.g., project = get_project(target_name)
        #       domains = project.get_assets('domain')
        #       social = project.get_assets('social')
        org = Organization(
            name=target_name,
            domains=["example.com"], # Stub: Replace with real data
            social_media_handles=["@example"] # Stub: Replace with real data
        )
        
        typer.echo(f"Generating OPSEC Footprint for {org.name}...")
        orchestrator = OpsecFootprint()
        report = orchestrator.generate_report(org)
        typer.echo(f"Report generation complete. Saved to: {report.get('report_path')}")
        
        save_or_print_results(report, output_file)
        save_scan_to_db(target=target_name, module="opsec_footprint_report", data=report)

    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    opsec_app()