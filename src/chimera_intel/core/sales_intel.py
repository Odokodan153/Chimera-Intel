"""
Sales & Business Intent Intelligence Module for Chimera Intel.

This module provides tools to find sales intent signals (like job
postings, RFPs) and win/loss signals (case studies, testimonials)
that indicate market position and churn.

This module implements functionality for:
- 7) Channel Performance & Retention Signals (inferred)
- 8) Sales / Win-Loss & Intent Signals
"""

import typer
import asyncio
import logging
import httpx
from typing import Optional, Dict, Any, List
from chimera_intel.core.http_client import async_client
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.project_manager import resolve_target

logger = logging.getLogger(__name__)
app = typer.Typer(
    no_args_is_help=True, help="Sales & Intent Intelligence (SALINT) tools."
)


async def _search_google_cse(
    query: str, api_key: str, cse_id: str, num_results: int = 10
) -> Dict[str, Any]:
    """
    Performs a real search using the Google Custom Search Engine (CSE) API.
    
    NOTE: This function is duplicated from 'channel_intel.py' to make
    this module self-contained without a major refactor of 'google_search.py'.
    In a future refactor, this should be moved to a shared 'search' utility.
    """
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": cse_id,
        "q": query,
        "num": num_results,
    }
    try:
        response = await async_client.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        logger.error(f"Google CSE API search failed for '{query}': {e}")
        return {"error": str(e), "items": []}


async def _run_searches(
    queries: List[str], api_key: str, cse_id: str
) -> List[Dict[str, str]]:
    """Helper to run a list of Google CSE search queries in parallel."""
    console.print(f"Searching Google CSE for {len(queries)} queries...")
    search_tasks = [
        _search_google_cse(q, api_key, cse_id, num_results=5) for q in queries
    ]
    search_api_results = await asyncio.gather(*search_tasks)

    found_items = []
    for i, api_result in enumerate(search_api_results):
        if "error" in api_result:
            logger.warning(
                f"Google CSE API error for query '{queries[i]}': {api_result['error']}"
            )
            continue

        for item in api_result.get("items", []):
            found_items.append({
                "source_query": queries[i],
                "title": item.get("title"),
                "link": item.get("link"),
                "snippet": item.get("snippet"),
            })
    return found_items


@app.command(name="find-intent-signals")
def find_intent_signals(
    domain: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Finds public intent signals (e.g., job postings, RFPs) and
    churn signals (e.g., hiring support, review complaints).
    """
    target_domain = resolve_target(domain, required_assets=["domain"])
    if not is_valid_domain(target_domain):
        console.print(f"[red]Invalid domain:[/red] '{target_domain}'")
        raise typer.Exit(code=1)

    # Check for required API keys
    google_api_key = API_KEYS.google_api_key
    google_cse_id = API_KEYS.google_cse_id
    if not google_api_key or not google_cse_id:
        console.print(
            "[red]Error: 'google_api_key' and 'google_cse_id' must be set.[/red]"
        )
        raise typer.Exit(code=1)

    console.print(
        f"Hunting for intent and retention signals for {target_domain}..."
    )

    # 7) Churn / Retention Early Signals
    # 8) Intent Signals
    search_queries = [
        # Job postings (Intent & Retention)
        f'"{target_domain}" "job opening" OR "hiring" "sales" OR "engineer"',
        f'"{target_domain}" "hiring" "customer support" OR "customer success"',
        f'site:linkedin.com/jobs "{target_domain}"',
        # Procurement notices, RFPs, public tenders (Intent)
        f'"{target_domain}" "RFP" OR "request for proposal"',
        f'"{target_domain}" "public tender" OR "procurement notice"',
        # Churn signals (public complaints)
        f'"{target_domain}" "customer complaints" OR "downgrades" site:reddit.com',
        f'"{target_domain}" "poor reviews" site:g2.com OR site:capterra.com',
    ]

    async def hunt():
        return await _run_searches(search_queries, google_api_key, google_cse_id)

    try:
        results = asyncio.run(hunt())
        final_report = {
            "domain": target_domain,
            "signal_type": "intent_and_retention",
            "signals_found": results,
        }
        console.print(
            f"[bold green]Found {len(results)} potential intent/retention signals.[/bold green]"
        )
        save_or_print_results(final_report, output_file)
    except Exception as e:
        logger.error(f"Error finding intent signals: {e}", exc_info=True)
        console.print(f"[red]An error occurred: {e}[/red]")
        raise typer.Exit(code=1)


@app.command(name="mine-win-loss")
def mine_win_loss_signals(
    domain: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Mines Google for win/loss signals like case studies,
    testimonials, and partner change announcements.
    """
    target_domain = resolve_target(domain, required_assets=["domain"])
    if not is_valid_domain(target_domain):
        console.print(f"[red]Invalid domain:[/red] '{target_domain}'")
        raise typer.Exit(code=1)

    # Check for required API keys
    google_api_key = API_KEYS.google_api_key
    google_cse_id = API_KEYS.google_cse_id
    if not google_api_key or not google_cse_id:
        console.print(
            "[red]Error: 'google_api_key' and 'google_cse_id' must be set.[/red]"
        )
        raise typer.Exit(code=1)

    console.print(f"Mining win/loss signals for {target_domain}...")

    # 8) Win/Loss Miner
    search_queries = [
        # Wins (Case studies, testimonials)
        f'"{target_domain}" "case study" OR "customer story"',
        f'"{target_domain}" "testimonial"',
        f'"we chose {target_domain}" OR "we selected {target_domain}"',
        # Losses (Competitor wins)
        f'"switched from {target_domain}" OR "moved away from {target_domain}"',
        f'"chose * over {target_domain}"',
        # Partner changes
        f'"{target_domain}" "new partner" OR "partner announcement"',
    ]

    async def hunt():
        return await _run_searches(search_queries, google_api_key, google_cse_id)

    try:
        results = asyncio.run(hunt())
        final_report = {
            "domain": target_domain,
            "signal_type": "win_loss",
            "signals_found": results,
        }
        console.print(
            f"[bold green]Found {len(results)} potential win/loss signals.[/bold green]"
        )
        save_or_print_results(final_report, output_file)
    except Exception as e:
        logger.error(f"Error mining win/loss signals: {e}", exc_info=True)
        console.print(f"[red]An error occurred: {e}[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()