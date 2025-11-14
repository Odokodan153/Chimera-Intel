"""
Internal Analytics & Lead Scoring Simulation Module for Chimera Intel.

This module provides tools to analyze data ALREADY collected by
Chimera and stored in the project database, simulating an
integration with internal analytics (CRM, CDP, etc.).

It addresses:
- 7) Channel Conversion Proxies (analyzing saved traffic/UTM/app data)
- 8) Lead Scoring Signals (using AI to score leads based on collected data)
"""

import typer
import json
import logging
from typing import Optional
from chimera_intel.core.utils import console, save_or_print_results
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.project_manager import resolve_target
from chimera_intel.core.database import get_aggregated_data_for_target
from chimera_intel.core.ai_core import generate_swot_from_data  

logger = logging.getLogger(__name__)
app = typer.Typer(
    no_args_is_help=True, help="Internal Analytics (INTA) simulation tools."
)


@app.command(name="correlate-proxies")
def correlate_conversion_proxies(
    domain: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Simulates finding conversion proxies by analyzing saved
    traffic, affiliate, and app review data from the database.
    """
    target = resolve_target(domain, required_assets=[])
    console.print(f"Correlating conversion proxies for {target} from saved data...")

    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data or not aggregated_data.get("modules"):
        console.print(
            f"[red]No aggregated data found for {target}. Run scans first.[/red]"
        )
        raise typer.Exit(code=1)

    modules = aggregated_data.get("modules", {})
    report = {"target": target, "analysis": [], "errors": []}

    # 1. Look for Channel Intel (Traffic Mix & UTMs)
    if "channel_intel" in modules:
        chan_data = modules["channel_intel"]
        
        # Check for traffic mix data
        mix_overview = chan_data.get("traffic_mix_overview")
        if mix_overview:
            report["analysis"].append(
                f"Found saved traffic mix data. Top source: "
                f"{max(mix_overview, key=mix_overview.get, default='N/A')}"
            )
        
        # Check for affiliate/partner data (as proxy for UTMs)
        partners = chan_data.get("potential_partners")
        if partners:
            report["analysis"].append(
                f"Found {len(partners)} potential affiliate/UTM patterns. "
                f"Example: {partners[0]['partner_page']}"
            )
        else:
            report["analysis"].append("No affiliate/UTM partner data found in scans.")
            
    else:
        report["errors"].append("Missing 'channel_intel' data for traffic analysis.")

    # 2. Look for VoC Intel (as proxy for App Installs)
    if "voc_intel" in modules:
        voc_data = modules["voc_intel"]
        total_reviews = voc_data.get("total_reviews_analyzed", 0)
        if total_reviews > 0:
            report["analysis"].append(
                f"Found App install/review activity: {total_reviews} reviews analyzed."
            )
    else:
        report["errors"].append("Missing 'voc_intel' data for app activity analysis.")

    console.print(
        f"[bold green]Conversion Proxy Correlation for {target}:[/bold green]"
    )
    save_or_print_results(report, output_file)


@app.command(name="score-leads")
def generate_lead_scoring_signals(
    domain: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Uses AI to generate a 'lead scoring' summary based on
    all collected intent and activity signals.
    """
    target = resolve_target(domain, required_assets=[])
    api_key = API_KEYS.google_api_key
    if not api_key:
        console.print("[red]Error: 'google_api_key' must be set for AI analysis.[/red]")
        raise typer.Exit(code=1)

    console.print(f"Generating AI lead scoring summary for {target}...")

    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data or not aggregated_data.get("modules"):
        console.print(
            f"[red]No aggregated data found for {target}. Run scans first.[/red]"
        )
        raise typer.Exit(code=1)

    data_str = json.dumps(aggregated_data.get("modules", {}), indent=2, default=str)

    prompt = f"""
    You are a sales operations analyst. Based on the following collected
    OSINT data for the target '{target}', generate a lead scoring summary.
    
    Identify signals that indicate high "intent" (e.g., job postings for
    related tools, RFPs, partner announcements) and "activity"
    (e.g., high ad spend, high direct traffic, recent customer reviews).
    
    Based on these signals, provide a qualitative "Lead Score" 
    (e.g., Hot, Warm, Cold) and a 1-paragraph justification.

    **Collected OSINT Data:**
    ```json
    {data_str}
    ```
    """

    try:
        # Re-using the generic text generation function
        with console.status("[bold cyan]AI is analyzing signals...[/bold cyan]"):
            result = generate_swot_from_data(prompt, api_key)
        
        if result.error:
            raise Exception(result.error)

        report = {
            "target": target,
            "ai_lead_score_summary": result.analysis_text
        }
        console.print(
            f"[bold green]AI-Generated Lead Scoring for {target}:[/bold green]"
        )
        save_or_print_results(report, output_file, is_rich=True)

    except Exception as e:
        logger.error(f"Error during AI lead scoring: {e}", exc_info=True)
        console.print(f"[red]An error occurred with the AI API: {e}[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()