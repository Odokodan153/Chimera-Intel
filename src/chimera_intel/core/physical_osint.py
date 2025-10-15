"""
Module for Physical Security OSINT.

Identifies and gathers intelligence on a target's physical locations.
"""

import typer
import logging
import googlemaps  # type: ignore
from typing import Optional
from .schemas import PhysicalSecurityResult, PhysicalLocation
from .config_loader import API_KEYS
from .utils import save_or_print_results
from .database import save_scan_to_db
from .project_manager import resolve_target

logger = logging.getLogger(__name__)


def find_physical_locations(query: str) -> PhysicalSecurityResult:
    """
    Finds physical office locations for a given company name using the Google Maps API.

    Args:
        query (str): The company name to search for (e.g., "Googleplex").

    Returns:
        PhysicalSecurityResult: A Pydantic model with the discovered locations.
    """
    api_key = API_KEYS.google_maps_api_key
    if not api_key:
        return PhysicalSecurityResult(
            query=query, error="Google Maps API key not found in .env file."
        )
    logger.info(f"Searching for physical locations matching query: {query}")

    try:
        gmaps = googlemaps.Client(key=api_key)

        # Use the Places API's "text search" to find locations

        places_result = gmaps.places(query=query)

        locations = []
        for place in places_result.get("results", []):
            lat = place.get("geometry", {}).get("location", {}).get("lat")
            lng = place.get("geometry", {}).get("location", {}).get("lng")

            if lat and lng:
                locations.append(
                    PhysicalLocation(
                        name=place.get("name"),
                        address=place.get("formatted_address"),
                        latitude=lat,
                        longitude=lng,
                        rating=place.get("rating"),
                    )
                )
        return PhysicalSecurityResult(query=query, locations_found=locations)
    except Exception as e:
        logger.error(f"Failed to find physical locations for '{query}': {e}")
        return PhysicalSecurityResult(query=query, error=f"An API error occurred: {e}")


# --- Typer CLI Application ---


physical_osint_app = typer.Typer()


@physical_osint_app.command("locations")
def run_location_search(
    target: Optional[str] = typer.Argument(
        None,
        help="The company name or search query. Uses active project's company name if not provided.",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Finds physical office locations related to a target."""
    target_query = resolve_target(target, required_assets=["company_name", "domain"])

    results_model = find_physical_locations(target_query)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_query, module="physical_osint_locations", data=results_dict
    )
