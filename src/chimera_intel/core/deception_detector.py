"""
Module for Corporate Deception & Mimicry Analysis.

Identifies hidden relationships between companies by finding shared digital
assets like IP addresses, SSL certificates, and WHOIS registration details.
"""

import typer
import asyncio
import logging
from typing import Optional, List, Dict
import httpx
from .schemas import DeceptionAnalysisResult, CorporateNetworkLink
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import resolve_target
from .footprint import gather_footprint_data

logger = logging.getLogger(__name__)


async def reverse_ip_lookup(ip: str) -> List[str]:
    """
    Finds other domains hosted on the same IP address using an online API.
    """
    domains = []
    try:
        async with httpx.AsyncClient() as client:
            # Using a free reverse IP lookup service. In a production environment,
            # a more robust, paid service would be preferable.

            response = await client.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            )
            response.raise_for_status()
            domains = response.text.splitlines()
    except httpx.HTTPStatusError as e:
        logger.warning(f"Reverse IP lookup failed for {ip}: {e.response.status_code}")
    except Exception as e:
        logger.error(f"An error occurred during reverse IP lookup for {ip}: {e}")
    return domains


async def analyze_for_deception(domain: str) -> DeceptionAnalysisResult:
    """
    Analyzes a target's footprint to find other entities sharing the same infrastructure.

    Args:
        domain (str): The primary domain to investigate.

    Returns:
        DeceptionAnalysisResult: A Pydantic model containing detected links.
    """
    logger.info(f"Starting deception analysis for {domain}")

    # Step 1: Get the initial footprint to find IP addresses

    console.print(f"[cyan]Gathering initial footprint for {domain}...[/cyan]")
    initial_footprint = await gather_footprint_data(domain)
    main_ips = set(initial_footprint.footprint.dns_records.get("A", []))

    if not main_ips:
        return DeceptionAnalysisResult(
            target=domain,
            summary="Analysis could not proceed: No A records found for the primary domain.",
            error="No IP addresses found for the target domain.",
        )
    # Step 2: Find other domains on the same IPs (Reverse IP Lookup)

    console.print(
        f"[cyan]Analyzing infrastructure related to IPs: {', '.join(main_ips)}...[/cyan]"
    )
    reverse_ip_tasks = [reverse_ip_lookup(ip) for ip in main_ips]
    potential_related_domains_lists = await asyncio.gather(*reverse_ip_tasks)
    potential_related_domains = {
        d for sublist in potential_related_domains_lists for d in sublist if d
    }

    # Step 3: Gather footprints for all potentially related domains

    tasks = [gather_footprint_data(d) for d in potential_related_domains if d != domain]
    all_footprints = await asyncio.gather(*tasks)
    all_footprints.append(
        initial_footprint
    )  # Add the initial footprint back in for comparison

    # Step 4: Cross-reference the data to find links

    console.print(
        "[cyan]Cross-referencing digital assets to find hidden links...[/cyan]"
    )
    detected_links: List[CorporateNetworkLink] = []

    # Simple example: Link companies sharing the same WHOIS email

    whois_data_map: Dict[str, Dict] = {}
    for fp in all_footprints:
        whois_data_map[fp.domain] = fp.footprint.whois_info
    emails_to_domains: Dict[str, List[str]] = {}
    for domain_name, whois_info in whois_data_map.items():
        email = whois_info.get("emails")
        if isinstance(email, list):
            email = email[0]  # Take the first email
        if email and isinstance(email, str):
            emails_to_domains.setdefault(email.lower(), []).append(domain_name)
    for email, domains in emails_to_domains.items():
        if len(domains) > 1:
            for i in range(len(domains)):
                for j in range(i + 1, len(domains)):
                    detected_links.append(
                        CorporateNetworkLink(
                            entity_a=domains[i],
                            entity_b=domains[j],
                            link_type="Shared Whois Email",
                            confidence="High",
                            details=f"Both domains are registered with the email: {email}",
                        )
                    )
    summary = f"Found {len(detected_links)} potential link(s) based on asset cross-referencing."

    return DeceptionAnalysisResult(
        target=domain, detected_links=detected_links, summary=summary
    )


# --- Typer CLI Application ---


deception_app = typer.Typer()


@deception_app.command("run")
async def run_deception_analysis(
    target: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Detects corporate mimicry and hidden networks via asset correlation.
    """
    target_name = resolve_target(target, required_assets=["domain"])

    results_model = await analyze_for_deception(target_name)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_name, module="deception_analysis", data=results_dict)
