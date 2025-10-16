"""
Module for Geopolitical Intelligence (GEOINT).

Analyzes a target's physical and digital footprint to assess risks related to its
geographic distribution, such as political instability or infrastructure dependencies.
"""

import typer
import logging
from typing import Optional, List, Set
import asyncio
from datetime import datetime

from .schemas import GeointReport, CountryRiskProfile
from .utils import save_or_print_results, console
from .database import get_aggregated_data_for_target, save_scan_to_db
from .http_client import sync_client
from .project_manager import resolve_target
from .geo_osint import get_geolocation_data

logger = logging.getLogger(__name__)


def get_country_risk_data(country_name: str) -> Optional[CountryRiskProfile]:
    """
    Fetches a risk profile for a given country using the restcountries.com and World Bank APIs.
    NOTE: A dedicated risk intelligence API would be required for production environments
    to get a wider range of metrics.
    """
    try:
        # --- Get general country data ---

        country_response = sync_client.get(
            f"https://restcountries.com/v3.1/name/{country_name}?fullText=true"
        )
        country_response.raise_for_status()
        country_data = country_response.json()[0]
        country_code = country_data.get(
            "cca2"
        )  # Get ISO 3166-1 alpha-2 country code for World Bank API

        # --- Get Political Stability Index from World Bank API ---

        political_stability = None
        if country_code:
            current_year = datetime.now().year - 1
            wb_url = f"http://api.worldbank.org/v2/country/{country_code}/indicator/PV.EST?date={current_year}:{current_year}&format=json"
            wb_response = sync_client.get(wb_url)
            wb_response.raise_for_status()
            wb_data = wb_response.json()
            if wb_data and len(wb_data) > 1 and wb_data[1]:
                political_stability = wb_data[1][0].get("value")
        return CountryRiskProfile(
            country_name=country_data.get("name", {}).get("common"),
            region=country_data.get("region"),
            subregion=country_data.get("subregion"),
            population=country_data.get("population"),
            political_stability_index=(
                round(political_stability, 2)
                if political_stability is not None
                else None
            ),
        )
    except Exception as e:
        logger.warning(f"Could not retrieve full risk data for {country_name}: {e}")
        return None


async def _get_countries_from_ips(ips: List[str]) -> Set[str]:
    """
    Asynchronously gets country names from a list of IP addresses.
    """
    tasks = [get_geolocation_data(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    countries = set()
    for res in results:
        if res and res.country:
            countries.add(res.country)
    return countries


async def generate_geoint_report(target: str) -> GeointReport:
    """
    Generates a GEOINT report by analyzing the geographic distribution of assets.
    """
    logger.info(f"Generating GEOINT report for {target}")
    aggregated_data = get_aggregated_data_for_target(target)
    if not aggregated_data:
        return GeointReport(target=target, error="No historical data found for target.")
    countries: Set[str] = set()
    modules = aggregated_data.get("modules", {})

    # Extract countries from physical locations

    physical_locs = modules.get("physical_osint_locations", {}).get(
        "locations_found", []
    )
    for loc in physical_locs:
        # A simple way to extract the country from the address

        country = loc.get("address", "").split(",")[-1].strip()
        if country:
            countries.add(country)
    # Extract countries from IP address geolocation from footprint data

    footprint_data = modules.get("footprint", {})
    if footprint_data:
        dns_records = footprint_data.get("dns_records", {})
        if dns_records:
            ip_addresses = dns_records.get("A", [])
            if ip_addresses:
                ip_countries = await _get_countries_from_ips(ip_addresses)
                countries.update(ip_countries)
    # Fetch risk profiles for each unique country

    risk_profiles: List[CountryRiskProfile] = []
    with console.status("[cyan]Fetching country risk profiles...[/cyan]"):
        for country in countries:
            profile = get_country_risk_data(country)
            if profile:
                risk_profiles.append(profile)
    return GeointReport(target=target, country_risk_profiles=risk_profiles)


geoint_app = typer.Typer()


@geoint_app.command("run")
def run_geoint_analysis(
    target: Optional[str] = typer.Argument(
        None, help="The target to analyze. Uses active project."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes a target's geographic footprint for geopolitical risks.
    """
    target_name = resolve_target(target, required_assets=["company_name", "domain"])
    results_model = asyncio.run(generate_geoint_report(target_name))
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_name, module="geoint_report", data=results_dict)
