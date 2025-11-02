"""
Module for Zero-Day Tracking.

Monitors security communities, forums, and vulnerability databases
for emerging exploits and potential zero-day threats.
"""

import logging
from typing import Optional, Dict, Any, List

import typer
from .config_loader import API_KEYS
from .database import save_scan_to_db
from .http_client import sync_client
from .schemas import EmergingExploit, ZeroDayTrackingResult
from .utils import console, save_or_print_results

logger = logging.getLogger(__name__)

# In a real implementation, this would point to a specialized
# exploit feed API (e.g., Exploit-DB, internal feeds)
EXPLOIT_FEED_API_URL = "https://api.mock-exploit-feed.com/v1/search"


def monitor_emerging_exploits(query: str) -> ZeroDayTrackingResult:
    """
    Searches exploit intelligence feeds for emerging threats related to a query.
    
    The query can be a product name (e.g., "Microsoft Exchange"),
    a vendor ("Adobe"), or a CVE ID.
    """
    api_key = API_KEYS.exploit_feed_api_key  # Assumes EXPLOIT_FEED_API_KEY
    if not api_key:
        return ZeroDayTrackingResult(
            query=query,
            error="Exploit Feed API key (EXPLOIT_FEED_API_KEY) is not configured.",
        )
    
    logger.info(f"Monitoring for emerging exploits related to: {query}")
    
    headers = {"X-API-KEY": api_key}
    # Search for recent exploits matching the query
    params = {"q": query, "sort": "discovered_desc", "limit": 20}

    try:
        response = sync_client.get(EXPLOIT_FEED_API_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        if not data.get("exploits"):
            return ZeroDayTrackingResult(
                query=query,
                summary=f"No emerging exploits found matching '{query}'.",
            )
            
        emerging_exploits: List[EmergingExploit] = []
        for ex in data.get("exploits", []):
            emerging_exploits.append(
                EmergingExploit(
                    exploit_id=ex.get("id", "N/A"),
                    product=ex.get("product", "Unknown"),
                    vendor=ex.get("vendor", "Unknown"),
                    description=ex.get("description", "No description."),
                    source_url=ex.get("source_url", "#"),
                    discovered_on=ex.get("discovered_on", "N/A"),
                    is_zero_day=ex.get("is_zero_day", False),
                )
            )

        summary = f"Found {len(emerging_exploits)} emerging exploits matching '{query}'."
        
        return ZeroDayTrackingResult(
            query=query,
            emerging_exploits=emerging_exploits,
            summary=summary,
        )

    except Exception as e:
        logger.error(f"An error occurred while querying exploit feed: {e}")
        return ZeroDayTrackingResult(
            query=query, error=f"An API error occurred: {e}"
        )


# --- Typer CLI Application ---

zeroday_app = typer.Typer()

@zeroday_app.command("monitor")
def run_zero_day_monitoring(
    query: str = typer.Argument(
        ..., help="The product, vendor, or CVE to monitor (e.g., 'Exchange', 'CVE-2023-5555')."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Monitors security feeds for emerging exploits and zero-days.
    """
    with console.status(
        f"[bold cyan]Monitoring for exploits matching '{query}'...[/bold cyan]"
    ):
        results_model = monitor_emerging_exploits(query)
    
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=query, module="zero_day_tracking", data=results_dict)