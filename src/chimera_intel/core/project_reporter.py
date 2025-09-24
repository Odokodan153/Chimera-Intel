"""
Module for generating automated, comprehensive project reports.

This module orchestrates multiple scans against an active project's targets,
aggregates the results, and generates a unified PDF dossier.
"""

import typer
import asyncio
import logging
from typing import Dict, Any, List, Union, cast
from .project_manager import get_active_project
from .config_loader import CONFIG, API_KEYS
from .utils import console
from .reporter import generate_pdf_report
from .footprint import gather_footprint_data
from .web_analyzer import gather_web_analysis_data
from .defensive import check_hibp_breaches
from .schemas import FootprintResult, WebAnalysisResult, HIBPResult

logger = logging.getLogger(__name__)

project_report_app = typer.Typer()


async def generate_project_report(output_path: str):
    """
    Orchestrates the generation of a full project intelligence report.
    """
    active_project = get_active_project()
    if not active_project:
        console.print(
            "[bold red]Error:[/bold red] No active project set. Use 'chimera project use <name>' first."
        )
        raise typer.Exit(code=1)
    domain = active_project.domain
    if not domain:
        console.print(
            "[bold red]Error:[/bold red] Active project has no domain set. A domain is required to generate a report."
        )
        raise typer.Exit(code=1)
    company_name = active_project.company_name or domain

    console.print(
        f"[bold cyan]Starting comprehensive report generation for project: {active_project.project_name}[/bold cyan]"
    )

    scans_to_run = CONFIG.reporting.project_report_scans
    tasks = []

    # --- Map scan names from config to their functions ---

    scan_map = {
        "footprint": gather_footprint_data(domain),
        "web_analyzer": gather_web_analysis_data(domain),
        "defensive_breaches": asyncio.to_thread(
            check_hibp_breaches, domain, API_KEYS.hibp_api_key or ""
        ),
    }

    for scan_name in scans_to_run:
        if scan_name in scan_map:
            console.print(f"  -> Queuing scan: [yellow]{scan_name}[/yellow]")
            tasks.append(scan_map[scan_name])
        else:
            logger.warning(f"Unknown scan type '{scan_name}' in config.yaml, skipping.")
    # --- Execute scans concurrently ---

    with console.status("[bold green]Executing intelligence modules...[/bold green]"):
        scan_results = cast(
            List[Union[FootprintResult, WebAnalysisResult, HIBPResult]],
            list(await asyncio.gather(*tasks)),
        )
    # --- Aggregate results into a single dictionary ---

    aggregated_data: Dict[str, Any] = {
        "project_name": active_project.project_name,
        "domain": domain,
        "company": company_name,
    }

    for i, scan_name in enumerate(scans_to_run):
        if scan_results[i]:
            # The result from each function is a Pydantic model, so we dump it to a dict

            aggregated_data[scan_name] = scan_results[i].model_dump(exclude_none=True)
    # --- Generate the final PDF report ---

    console.print(
        f"[bold cyan]Aggregating data and generating PDF report at: {output_path}[/bold cyan]"
    )
    generate_pdf_report(aggregated_data, output_path)

    console.print(
        f"[bold green]✅ Project report for '{active_project.project_name}' generated successfully![/bold green]"
    )


@project_report_app.command("run")
def create_project_report():
    """
    Generates a comprehensive PDF report for the active project.

    This command automatically runs a predefined set of scans against the
    active project's targets, aggregates all results, and compiles them
    into a single, professional PDF dossier. The scans to be run can be
    configured in the `config.yaml` file.
    """
    active_project = get_active_project()
    if not active_project:
        console.print("[bold red]Error:[/bold red] No active project set.")
        raise typer.Exit(code=1)
    output_filename = (
        f"Chimera_Report_{active_project.project_name.replace(' ', '_')}.pdf"
    )

    asyncio.run(generate_project_report(output_filename))
