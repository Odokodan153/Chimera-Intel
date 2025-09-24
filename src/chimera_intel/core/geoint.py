"""
Module for Geopolitical Intelligence (GEOINT).

Analyzes a target's physical and digital footprint to assess risks related to its
geographic distribution, such as political instability or infrastructure dependencies.
"""

import typer
import logging
from typing import Optional, List, Set

from .schemas import GeointReport, CountryRiskProfile
from .utils import save_or_print_results, console
from .database import get_aggregated_data_for_target, save_scan_to_db
from .http_client import sync_client
from .project_manager import resolve_target

logger = logging.getLogger(__name__)


def get_country_risk_data(country_name: str) -> Optional[CountryRiskProfile]:
    """
    Fetches a risk profile for a given country.

    NOTE: This is a placeholder for a real risk data provider API.
    This example uses a public API for general country data.
    """
    try:
        # Using a public API for demonstration purposes.
        # A real implementation would use a dedicated risk intelligence API.

        response = sync_client.get(
            f"https://restcountries.com/v3.1/name/{country_name}"
        )
        response.raise_for_status()
        data = response.json()[0]

        return CountryRiskProfile(
            country_name=data.get("name", {}).get("common"),
            region=data.get("region"),
            subregion=data.get("subregion"),
            population=data.get("population"),
            # Placeholder for real risk scores
            political_stability_index=6.5,  # Example static value
            economic_freedom_index=7.0,  # Example static value
        )
    except Exception as e:
        logger.warning(f"Could not retrieve risk data for {country_name}: {e}")
        return None


def generate_geoint_report(target: str) -> GeointReport:
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
    # Extract countries from IP address geolocation

    ip_intel = modules.get("footprint", {}).get("ip_threat_intelligence", [])
    for intel in ip_intel:
        # This assumes a geo-intel module has run and saved data previously
        # For a full implementation, this would need to query the geo_osint data

        pass  # Placeholder for more advanced correlation
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
    results_model = generate_geoint_report(target_name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_name, module="geoint_report", data=results_dict)
