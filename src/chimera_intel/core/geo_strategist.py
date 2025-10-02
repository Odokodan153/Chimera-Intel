"""
Module for Geo-Strategic Analysis.

Synthesizes data from multiple intelligence modules to build a comprehensive
picture of a target's geographic footprint and key operational centers.
"""

import typer
import logging
from typing import List, Dict, Optional
from .schemas import GeoStrategicReport, OperationalCenter
from .database import get_aggregated_data_for_target
from .utils import save_or_print_results
from .database import save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)


def generate_geo_strategic_report(target: str) -> GeoStrategicReport:
    """
    Analyzes aggregated data to identify and report on a target's geographic footprint.

    This function acts as an orchestrator, pulling data from physical_osint,
    corporate_intel (hiring), and ecosystem_intel (distributors) to create a
    holistic view of a company's operational locations.

    Args:
        target (str): The primary target of the analysis (company name or domain).

    Returns:
        GeoStrategicReport: A Pydantic model containing the synthesized report.
    """
    logger.info(f"Generating Geo-Strategic report for {target}")
    aggregated_data = get_aggregated_data_for_target(target)
    operational_centers: List[OperationalCenter] = []
    processed_locations: Dict[str, OperationalCenter] = {}

    if not aggregated_data or not aggregated_data.get("modules"):
        return GeoStrategicReport(
            target=target,
            error="Not enough historical data to generate a report. Run other scans first.",
        )
    modules = aggregated_data.get("modules", {})

    # 1. Extract data from Physical OSINT (Official Offices)

    physical_data = modules.get("physical_osint_locations", {}).get(
        "locations_found", []
    )
    for loc in physical_data:
        key = loc.get("name", "").lower()
        if key and key not in processed_locations:
            center = OperationalCenter(
                location_name=loc.get("name"),
                address=loc.get("address"),
                location_type="Corporate Office / Physical Location",
                source_modules=["physical_osint"],
                details=f"Google Maps rating: {loc.get('rating', 'N/A')}",
            )
            processed_locations[key] = center
    # 2. Extract data from Corporate Intel (Hiring Locations)

    hiring_data = (
        modules.get("corporate_hr_intel", {})
        .get("hiring_trends", {})
        .get("job_postings", [])
    )
    for job in hiring_data:
        location_str = job.get("location")
        if location_str:
            key = location_str.lower()
            if key in processed_locations:
                processed_locations[key].source_modules.append("corporate_hr_intel")
                processed_locations[key].details += f"; Hiring for '{job.get('title')}'"
            else:
                center = OperationalCenter(
                    location_name=location_str,
                    location_type="Hiring Area",
                    source_modules=["corporate_hr_intel"],
                    details=f"Hiring for role: '{job.get('title')}'",
                )
                processed_locations[key] = center
    # 3. Extract data from Ecosystem Intel (Distributor Locations)

    distributor_data = (
        modules.get("ecosystem_analysis", {})
        .get("ecosystem_data", {})
        .get("distributors", [])
    )
    for dist in distributor_data:
        location_str = dist.get("location")
        if location_str:
            key = location_str.lower()
            if key in processed_locations:
                processed_locations[key].source_modules.append("ecosystem_intel")
                processed_locations[
                    key
                ].details += f"; Distributor: '{dist.get('distributor_name')}'"
            else:
                center = OperationalCenter(
                    location_name=location_str,
                    location_type="Supply Chain / Distribution Hub",
                    source_modules=["ecosystem_intel"],
                    details=f"Distributor: '{dist.get('distributor_name')}'",
                )
                processed_locations[key] = center
    operational_centers = list(processed_locations.values())
    return GeoStrategicReport(target=target, operational_centers=operational_centers)


# --- Typer CLI Application ---


geo_strategist_app = typer.Typer()


@geo_strategist_app.command("run")
def run_geo_strategy_analysis(
    target: Optional[str] = typer.Argument(
        None, help="The target to analyze. Uses active project if not provided."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Synthesizes data to create a geographic intelligence report."""
    target_name = resolve_target(target, required_assets=["domain", "company_name"])

    results_model = generate_geo_strategic_report(target_name)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_name, module="geo_strategist", data=results_dict)
