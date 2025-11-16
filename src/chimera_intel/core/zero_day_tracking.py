"""
Module for Zero-Day Tracking.

Monitors security communities, forums, and vulnerability databases
for emerging exploits and potential zero-day threats.

This module has been updated to use the NVD API 2.0.
"""

import logging
from typing import Optional, List
import typer
from .config_loader import API_KEYS
from .database import save_scan_to_db
from .http_client import sync_client
from .schemas import EmergingExploit, ZeroDayTrackingResult
from .utils import console, save_or_print_results

logger = logging.getLogger(__name__)

# Updated to NVD API 2.0 endpoint for CVEs
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def monitor_emerging_exploits(query: str) -> ZeroDayTrackingResult:
    """
    Searches the NVD for CVEs related to a query.
    
    The query can be a product name (e.g., "Microsoft Exchange"),
    a vendor ("Adobe"), or a CVE ID.
    """
    # This key is now used for the NVD API.
    # Request one here: https://nvd.nist.gov/developers/request-an-api-key
    api_key = API_KEYS.exploit_feed_api_key
    if not api_key:
        return ZeroDayTrackingResult(
            query=query,
            error="NVD API key (set as EXPLOIT_FEED_API_KEY) is not configured.",
        )
    
    logger.info(f"Monitoring NVD for CVEs related to: {query}")
    
    # NVD API 2.0 requires the key in the header
    headers = {"apiKey": api_key}
    # NVD API 2.0 uses 'keywordSearch' for text search
    params = {"keywordSearch": query, "resultsPerPage": 20}

    try:
        response = sync_client.get(NVD_API_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        if not data.get("vulnerabilities"):
            return ZeroDayTrackingResult(
                query=query,
                summary=f"No CVEs found matching '{query}'.",
            )
            
        emerging_exploits: List[EmergingExploit] = []
        # The main list is under the 'vulnerabilities' key
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            
            exploit_id = cve_data.get("id", "N/A")
            
            # Get English description
            description = "No description."
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "No description.")
                    break
            
            # Get a reference URL
            source_url = f"https://nvd.nist.gov/vuln/detail/{exploit_id}"
            if cve_data.get("references"):
                source_url = cve_data["references"][0].get("url", source_url)

            # Use CISA KEV presence to flag if it's "known exploited"
            # The 'exploitAdd' field is present if it's in CISA's KEV catalog
            is_known_exploited = cve_data.get("exploitAdd") is not None

            emerging_exploits.append(
                EmergingExploit(
                    exploit_id=exploit_id,
                    product="N/A", # NVD product data is in CPE format, requires complex parsing
                    vendor="N/A",  # This would require more complex CPE parsing
                    description=description,
                    source_url=source_url,
                    discovered_on=cve_data.get("published", "N/A"),
                    is_zero_day=is_known_exploited, # Flag if CISA lists it as exploited
                )
            )

        summary = f"Found {len(emerging_exploits)} CVEs matching '{query}'."
        
        return ZeroDayTrackingResult(
            query=query,
            emerging_exploits=emerging_exploits,
            summary=summary,
        )

    except Exception as e:
        logger.error(f"An error occurred while querying NVD API: {e}")
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
    Monitors NVD for public CVEs matching a query.
    """
    with console.status(
        f"[bold cyan]Querying NVD for CVEs matching '{query}'...[/bold cyan]"
    ):
        results_model = monitor_emerging_exploits(query)
    
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=query, module="zero_day_tracking", data=results_dict)