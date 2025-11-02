"""
Physical OSINT Module (Chimera-Intel).

Provides tools to gather and analyze physical infrastructure information for target companies, including:

- Finding physical office locations via Google Maps.
- Extracting building footprints from OpenStreetMap.
- Mapping logistics routes between addresses.
- Aggregating facility and asset information in structured results.

Includes Typer CLI commands for direct usage.
"""

import typer
import logging
import googlemaps  # type: ignore
from typing import Optional, List, Dict, Any
from .schemas import (
    PhysicalSecurityResult, 
    PhysicalLocation, 
    BuildingFootprint, 
    FacilityMapResult  # New schemas
)
from .config_loader import API_KEYS
from .utils import save_or_print_results
from .database import save_scan_to_db
from .project_manager import resolve_target
from .http_client import sync_client  

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

def get_building_footprints(
    lat: float, lon: float, radius: int = 250
) -> List[BuildingFootprint]:
    """
    Gets building footprints around a coordinate from OpenStreetMap Overpass API.
    """
    overpass_url = "https://overpass-api.de/api/interpreter"
    # Overpass QL query to find building 'ways' (polygons) around a point
    query = f"""
    [out:json][timeout:25];
    (
      way(around:{radius},{lat},{lon})["building"];
    );
    out geom;
    """
    try:
        response = sync_client.post(overpass_url, data=query)
        response.raise_for_status()
        data = response.json()
        
        footprints = []
        for element in data.get("elements", []):
            if element.get("type") == "way" and element.get("geometry"):
                footprints.append(
                    BuildingFootprint(
                        osm_id=element.get("id"),
                        type=element.get("type"),
                        tags=element.get("tags", {}),
                        geometry=element.get("geometry", []),
                    )
                )
        return footprints
    except Exception as e:
        logger.error(f"Failed to get building footprints from Overpass API: {e}")
        return []

def get_logistics_route(origin_address: str, destination_address: str) -> Optional[Dict[str, Any]]:
    """
    Gets a logistics route (directions) between two addresses using Google Maps.
    """
    api_key = API_KEYS.google_maps_api_key
    if not api_key:
        logger.warning("Cannot get route, Google Maps API key not found.")
        return None
    
    try:
        gmaps = googlemaps.Client(key=api_key)
        directions_result = gmaps.directions(origin_address, destination_address, mode="driving")
        
        if not directions_result:
            return None
            
        # Return a simplified summary
        route = directions_result[0]
        return {
            "summary": route.get("summary"),
            "distance": route.get("legs", [{}])[0].get("distance", {}).get("text"),
            "duration": route.get("legs", [{}])[0].get("duration", {}).get("text"),
            "copyrights": route.get("copyrights"),
        }
    except Exception as e:
        logger.error(f"Failed to calculate route between '{origin_address}' and '{destination_address}': {e}")
        return None

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


@physical_osint_app.command("map-facility")
def run_facility_mapping(
    target: Optional[str] = typer.Argument(
        None,
        help="The company name or search query. Uses active project's company name.",
    ),
    map_route_from: Optional[str] = typer.Option(
        None, "--route-from", help="Optional origin address for logistics route mapping."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Maps facilities, building footprints, and logistics routes for a target.
    """
    target_query = resolve_target(target, required_assets=["company_name", "domain"])
    
    # 1. Find primary location
    location_result = find_physical_locations(target_query)
    if location_result.error or not location_result.locations_found:
        typer.echo(f"Could not find primary location for {target_query}.")
        raise typer.Exit(code=1)
        
    primary_location = location_result.locations_found[0]
    lat, lon = primary_location.latitude, primary_location.longitude
    typer.echo(f"Found primary location: {primary_location.address} ({lat}, {lon})")

    # 2. Get building footprints around it
    typer.echo("Fetching building footprints from OpenStreetMap...")
    footprints = get_building_footprints(lat, lon)
    
    # 3. Get logistics route if requested
    route = None
    if map_route_from:
        typer.echo(f"Calculating logistics route from '{map_route_from}'...")
        route = get_logistics_route(map_route_from, primary_location.address)

    results_model = FacilityMapResult(
        query=target_query,
        locations_found=location_result.locations_found,
        building_footprints=footprints,
        logistics_route=route,
    )
    
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_query, module="physical_osint_facility_map", data=results_dict
    )