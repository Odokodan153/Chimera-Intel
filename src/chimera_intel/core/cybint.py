"""
Module for the Cyber Intelligence (CYBINT) Suite.

This module provides a suite of tools for proactive cyber defense, including
attack surface management, threat actor profiling, and threat hunting.
"""

import typer
import logging
import asyncio
import json

from .schemas import AttackSurfaceReport
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .config_loader import API_KEYS
from typing import Optional
from .footprint import gather_footprint_data
from .vulnerability_scanner import run_vulnerability_scan
from .defensive import analyze_mozilla_observatory
from .offensive import discover_apis
from .ai_core import generate_swot_from_data  # Re-using this for AI analysis
from .project_manager import get_active_project


logger = logging.getLogger(__name__)


async def generate_attack_surface_report(domain: str) -> AttackSurfaceReport:
    """
    Orchestrates a full attack surface analysis by running multiple modules
    and generating an AI-powered risk assessment.

    Args:
        domain (str): The root domain of the target to assess.

    Returns:
        AttackSurfaceReport: A Pydantic model containing the aggregated results and AI summary.
    """
    logger.info(f"Starting comprehensive attack surface analysis for {domain}")

    # --- Step 1: Run core scans concurrently ---

    with console.status(
        "[bold cyan]Gathering intelligence from multiple modules...[/bold cyan]"
    ):
        footprint_task = gather_footprint_data(domain)
        # Vulnerability scanner is sync, so we run it in a thread

        vuln_scan_task = asyncio.to_thread(
            run_vulnerability_scan, domain
        )  # API key is handled internally
        observatory_task = asyncio.to_thread(analyze_mozilla_observatory, domain)
        api_discover_task = discover_apis(domain)

        (
            footprint_results,
            vuln_results,
            observatory_results,
            api_results,
        ) = await asyncio.gather(
            footprint_task, vuln_scan_task, observatory_task, api_discover_task
        )
    # --- Step 2: Aggregate data for AI analysis ---

    console.print("[bold cyan]Aggregating data for AI risk assessment...[/bold cyan]")
    summary_data = {
        "target": domain,
        "footprint_summary": {
            "total_subdomains": footprint_results.footprint.subdomains.total_unique,
            "ip_addresses": footprint_results.footprint.dns_records.get("A"),
            "ip_threat_intel_hits": len(
                footprint_results.footprint.ip_threat_intelligence
            ),
        },
        "vulnerability_summary": {
            "total_hosts_scanned": len(vuln_results.scanned_hosts),
            "critical_vulnerabilities": [
                f"{host.host}: {cve.id} (CVSS: {cve.cvss_score})"
                for host in vuln_results.scanned_hosts
                for port in host.open_ports
                for cve in port.vulnerabilities
                if cve.cvss_score >= 9.0
            ],
        },
        "web_security_posture": {
            "grade": observatory_results.grade if observatory_results else "N/A",
            "score": observatory_results.score if observatory_results else "N/A",
        },
        "exposed_apis": [api.url for api in api_results.discovered_apis],
    }

    # --- Step 3: Generate AI Risk Assessment ---

    ai_summary = "AI analysis skipped: GOOGLE_API_KEY not configured."
    google_api_key = API_KEYS.google_api_key
    if google_api_key:
        with console.status(
            "[bold cyan]Generating AI-powered risk summary...[/bold cyan]"
        ):
            prompt = f"""
            As a senior penetration tester and cyber threat analyst, your task is to provide a concise Attack Surface Risk Assessment
            for the domain '{domain}' based ONLY on the following JSON data summary.

            Do not mention that you are an AI. Present the output in Markdown format.
            Start with a one-sentence conclusion stating the overall risk level (e.g., "Risk Level: CRITICAL").
            Then, identify the top 3 most critical and likely attack vectors. For each vector, provide a brief, actionable recommendation.

            SCAN DATA SUMMARY:
            ```json
            {json.dumps(summary_data, indent=2)}
            ```
            """
            summary_result = generate_swot_from_data(
                prompt, google_api_key
            )  # Re-using the generic AI function
            if summary_result and not summary_result.error:
                ai_summary = summary_result.analysis_text
    # --- Step 4: Assemble the final report ---

    return AttackSurfaceReport(
        target_domain=domain,
        ai_risk_assessment=ai_summary,
        full_footprint_data=footprint_results,
        vulnerability_scan_results=vuln_results,
        web_security_posture=observatory_results,
        api_discovery_results=api_results,
    )


# --- Typer CLI Application ---


cybint_app = typer.Typer()


@cybint_app.command("attack-surface")
def run_attack_surface_analysis(
    domain: Optional[str] = typer.Argument(
        None, help="The root domain to assess. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save the full report to a JSON file."
    ),
):
    """
    Runs a comprehensive attack surface analysis and generates an AI risk assessment.
    """
    asyncio.run(async_run_attack_surface_analysis(domain, output_file))


async def async_run_attack_surface_analysis(
    domain: Optional[str], output_file: Optional[str]
):
    target_domain = domain
    if not target_domain:
        active_project = get_active_project()
        if active_project and active_project.domain:
            target_domain = active_project.domain
            console.print(
                f"[bold cyan]Using domain '{target_domain}' from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] No domain provided and no active project set."
            )
            raise typer.Exit(code=1)
    if not target_domain:
        console.print("[bold red]Error:[/bold red] A domain is required for this scan.")
        raise typer.Exit(code=1)
    results_model = await generate_attack_surface_report(target_domain)
    results_dict = results_model.model_dump(exclude_none=True)

    if not output_file:
        console.print("\n" + "=" * 50)
        console.print(
            f"[bold green]Attack Surface Risk Assessment for: {target_domain}[/bold green]"
        )
        console.print("=" * 50 + "\n")
        console.print(results_model.ai_risk_assessment)
        console.print("\n" + "-" * 50)
        console.print(
            "[dim]Full detailed results are available in the JSON output.[/dim]"
        )
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_domain, module="cybint_attack_surface", data=results_dict
    )
