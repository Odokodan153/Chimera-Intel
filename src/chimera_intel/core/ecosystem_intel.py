"""
Module for Ecosystem Intelligence.

Analyzes a target's business ecosystem to identify partners, competitors,
distributors, and other key relationships by synthesizing data from multiple APIs.
"""

import typer
import logging
import asyncio
from typing import List, Optional
from collections import Counter
import re

from .schemas import (
    EcosystemResult,
    EcosystemData,
    DiscoveredPartner,
    DiscoveredCompetitor,
    DiscoveredDistributor,
)
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .config_loader import API_KEYS
from .business_intel import get_news_gnews
from .web_analyzer import get_tech_stack_wappalyzer
from .corporate_intel import get_trade_data  # <-- IMPORT for distributor data
from .http_client import async_client
from .project_manager import get_active_project

logger = logging.getLogger(__name__)


async def find_partners(company_name: str, domain: str) -> List[DiscoveredPartner]:
    """
    Identifies a company's business partners.
    """
    logger.info(f"Searching for partners of {company_name}")
    partners: List[DiscoveredPartner] = []

    # --- Technique 1: News & Press Release Analysis (GNews API) ---

    gnews_key = API_KEYS.gnews_api_key
    if gnews_key:
        query = f'"{company_name}" AND (partnership OR collaboration OR integrates OR "powered by")'
        news_results = await get_news_gnews(query, gnews_key)
        if news_results and news_results.articles:
            for article in news_results.articles:
                potential_partners = re.findall(
                    r"\b([A-Z][A-Za-z-&']+(?:\s[A-Z][A-Za-z-&']+)*)\b", article.title
                )
                for partner in potential_partners:
                    if company_name.lower() not in partner.lower() and len(partner) > 3:
                        partners.append(
                            DiscoveredPartner(
                                partner_name=partner,
                                source="GNews API",
                                details=f"Mentioned in article: '{article.title}'",
                                confidence="Medium",
                            )
                        )
                        # Removed the premature break statement to find all partners in a title
    # --- Technique 2: Inferred Partnership from Tech Stack (Wappalyzer API) ---

    wappalyzer_key = API_KEYS.wappalyzer_api_key
    if wappalyzer_key:
        partner_tech_keywords = [
            "Salesforce",
            "HubSpot",
            "Stripe",
            "Shopify",
            "Oracle",
            "SAP",
        ]
        tech_stack = await get_tech_stack_wappalyzer(domain, wappalyzer_key)
        for tech in tech_stack:
            for keyword in partner_tech_keywords:
                if keyword.lower() in tech.lower():
                    partners.append(
                        DiscoveredPartner(
                            partner_name=keyword,
                            source="Wappalyzer API",
                            details=f"Detected use of '{tech}' technology on website.",
                            confidence="Medium",
                        )
                    )
    return partners


async def find_competitors(domain: str) -> List[DiscoveredCompetitor]:
    """
    Identifies a company's competitors using the SimilarWeb API.
    """
    logger.info(f"Searching for competitors of {domain}")
    competitors: List[DiscoveredCompetitor] = []

    # --- Technique: Similar Site Analysis (SimilarWeb API) ---

    similarweb_key = API_KEYS.similarweb_api_key
    if similarweb_key:
        url = f"https://api.similarweb.com/v1/website/{domain}/similar-sites/similarsites?api_key={similarweb_key}"
        try:
            response = await async_client.get(url)
            response.raise_for_status()
            data = response.json()
            for site in data.get("similar_sites", []):
                competitors.append(
                    DiscoveredCompetitor(
                        competitor_name=site.get("site"),
                        source="SimilarWeb API",
                        details=f"Similarity score: {site.get('score', 0):.2f}",
                        confidence="High",
                    )
                )
        except Exception as e:
            logger.error(f"Failed to get competitor data from SimilarWeb API: {e}")
    return competitors


async def find_distributors(company_name: str) -> List[DiscoveredDistributor]:
    """
    Identifies a company's distributors by analyzing trade data.
    """
    logger.info(f"Searching for distributors of {company_name}")
    distributors: List[DiscoveredDistributor] = []

    # --- Technique: Trade Data Analysis (ImportGenius API) ---
    # This is a synchronous function, so we run it in a separate thread

    trade_data_result = await asyncio.to_thread(get_trade_data, company_name)

    if trade_data_result and trade_data_result.shipments:
        # Count how many times each consignee appears in the shipment data

        consignee_counts = Counter(
            shipment.consignee
            for shipment in trade_data_result.shipments
            if shipment.consignee
        )

        # Report the most frequent consignees as likely distributors

        for name, count in consignee_counts.most_common(10):
            if company_name.lower() not in name.lower():  # Filter out self-references
                distributors.append(
                    DiscoveredDistributor(
                        distributor_name=name,
                        source="ImportGenius API",
                        details=f"Listed as consignee in {count} shipment(s).",
                        confidence="High",
                    )
                )
    return distributors


# --- Typer CLI Application ---

ecosystem_app = typer.Typer()


@ecosystem_app.command()  
def run(  # FIX: Renamed function from run_full_ecosystem_analysis
    company_name: Optional[str] = typer.Argument(
        None,
        help="The name of the target company. Uses active project if not provided.",
    ),
    domain: Optional[str] = typer.Argument(
        None,
        help="The primary domain of the target company. Uses active project if not provided.",
    ),
    output_file: Optional[str] = typer.Option(  
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes a company's full business ecosystem (partners, competitors, distributors).
    """
    # This function is now a synchronous wrapper around the async logic.

    asyncio.run(async_run_full_ecosystem_analysis(company_name, domain, output_file))


async def async_run_full_ecosystem_analysis(
    company_name: Optional[str],
    domain: Optional[str],
    output_file: Optional[str],
):
    target_company = company_name
    target_domain = domain

    if not all([target_company, target_domain]):
        active_project = get_active_project()
        if active_project:
            if not target_company:
                target_company = active_project.company_name
            if not target_domain:
                target_domain = active_project.domain
            console.print(
                f"[bold cyan]Using targets from active project '{active_project.project_name}'.[/bold cyan]"
            )
        else:
            console.print(
                "[bold red]Error:[/bold red] Company name and domain must be provided, or an active project must be set."
            )
            raise typer.Exit(code=1)
    if not target_company or not target_domain:
        console.print(
            "[bold red]Error:[/bold red] Missing company name or domain after checking project. Both are required."
        )
        raise typer.Exit(code=1)
    # Run all discovery tasks concurrently for maximum efficiency

    partners_task = find_partners(target_company, target_domain)
    competitors_task = find_competitors(target_domain)
    distributors_task = find_distributors(target_company)

    discovered_partners, discovered_competitors, discovered_distributors = (
        await asyncio.gather(partners_task, competitors_task, distributors_task)
    )

    ecosystem_data = EcosystemData(
        partners=discovered_partners,
        competitors=discovered_competitors,
        distributors=discovered_distributors,
    )

    results_model = EcosystemResult(
        target_company=target_company, ecosystem_data=ecosystem_data
    )

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_company, module="ecosystem_analysis", data=results_dict
    )