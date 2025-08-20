import typer
import asyncio
import logging
import json
from .schemas import TPRMReport, HIBPResult
from .vulnerability_scanner import run_vulnerability_scan
from .defensive import check_hibp_breaches
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .config_loader import API_KEYS

logger = logging.getLogger(__name__)


async def run_full_tpr_scan(domain: str) -> TPRMReport:
    """
    Orchestrates a full Third-Party Risk Management scan by running multiple modules.

    Args:
        domain (str): The domain of the third party to assess.

    Returns:
        TPRMReport: An aggregated report with a final AI-generated summary.
    """
    # Run scans concurrently

    vuln_scan_task = asyncio.to_thread(run_vulnerability_scan, domain)

    hibp_api_key = API_KEYS.hibp_api_key
    # Only create a breach scan task if the API key exists

    if hibp_api_key:
        breach_scan_task = asyncio.to_thread(check_hibp_breaches, domain, hibp_api_key)
        vuln_results, breach_results = await asyncio.gather(
            vuln_scan_task, breach_scan_task
        )
    else:
        # If no key, just run the vuln scan and create a default breach result

        vuln_results = await vuln_scan_task
        breach_results = HIBPResult(error="HIBP API key not configured.")
    # Prepare data for AI summary

    summary_data = {
        "target": domain,
        "modules": {
            "vulnerability_scan": vuln_results.model_dump(exclude_none=True),
            "data_breaches": breach_results.model_dump(exclude_none=True),
        },
    }

    # Generate AI Summary

    ai_summary = "AI analysis skipped: GOOGLE_API_KEY not configured."
    google_api_key = API_KEYS.google_api_key
    if google_api_key:
        prompt = f"""
        As a senior cybersecurity risk analyst, provide a concise Third-Party Risk Management (TPRM) summary
        for the domain '{domain}' based ONLY on the following JSON data.
        Focus on the most critical findings. Start with a one-sentence conclusion (e.g., "Risk Level: HIGH").
        Then, list 2-3 key findings as bullet points.

        SCAN DATA:
        ```json
        {json.dumps(summary_data, indent=2)}
        ```
        """
        # We can reuse the SWOT function as it's a generic prompt executor

        from .ai_core import generate_swot_from_data

        summary_result = generate_swot_from_data(prompt, google_api_key)
        if summary_result and not summary_result.error:
            ai_summary = summary_result.analysis_text
    return TPRMReport(
        target_domain=domain,
        ai_summary=ai_summary,
        vulnerability_scan_results=vuln_results,
        breach_results=breach_results,
    )


# --- Typer CLI Application ---

tpr_app = typer.Typer()


@tpr_app.command("run")
def run_tpr_scan_command(
    domain: str = typer.Argument(..., help="The third-party domain to assess."),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save the full report to a JSON file."
    ),
):
    """
    Runs a comprehensive TPRM scan against a target domain.
    """
    with console.status(
        f"[bold cyan]Running comprehensive TPRM scan on {domain}... This may take a while.[/bold cyan]"
    ):
        results_model = asyncio.run(run_full_tpr_scan(domain))
    console.print(f"\n--- [bold]Third-Party Risk Summary for {domain}[/bold] ---")
    console.print(results_model.ai_summary)
    console.print("---")

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        save_scan_to_db(target=domain, module="tpr_report", data=results_dict)
