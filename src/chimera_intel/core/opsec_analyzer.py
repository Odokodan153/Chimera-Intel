"""
Module for Operational Security (OPSEC) Analysis.

Correlates data from multiple scans to find potential OPSEC weaknesses, such as
developers using compromised credentials.
"""

import typer
import logging
from typing import Optional, List, Set

from .schemas import OpsecReport, CompromisedCommitter
from .utils import save_or_print_results
from .database import get_aggregated_data_for_target, save_scan_to_db
from .project_manager import resolve_target

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
        # A simple but effective correlation: check if any committer email appears in a breach.
        # A real implementation might query the HIBP API for each email.

        breached_emails_in_org = {
            email
            for breach in breach_data
            for email in breach.get("DataClasses", [])
            if "@" in email
        }

        for email in committer_emails:
            if email in breached_emails_in_org:
                compromised_committers.append(
                    CompromisedCommitter(
                        email=email,
                        source_repository=modules.get("code_intel_repo", {}).get(
                            "repository_url"
                        ),
                        related_breaches=[
                            b.get("Name") for b in breach_data
                        ],  # Simplified
                    )
                )
    return OpsecReport(target=target, compromised_committers=compromised_committers)


opsec_app = typer.Typer()


@opsec_app.command("run")
def run_opsec_analysis(
    target: Optional[str] = typer.Argument(
        None, help="The target to analyze. Uses active project."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Correlates scan data to find operational security (OPSEC) weaknesses.
    """
    target_name = resolve_target(target, required_assets=["company_name", "domain"])
    results_model = generate_opsec_report(target_name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_name, module="opsec_report", data=results_dict)
