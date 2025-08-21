import typer
import asyncio
import logging
import folium  # <-- Import the new library
from typing import List, Optional
from chimera_intel.core.schemas import GeoIntelResult, GeoIntelData
from chimera_intel.core.http_client import async_client
from chimera_intel.core.utils import save_or_print_results
from chimera_intel.core.database import save_scan_to_db

logger = logging.getLogger(__name__)


async def get_geolocation_data(ip_address: str) -> Optional[GeoIntelData]:
    """
    Retrieves geolocation data for a given IP address using the IP-API.com service.

    Args:
        ip_address (str): The IP address to geolocate.

    Returns:
        Optional[GeoIntelData]: A Pydantic model with the geolocation data, or None on error.
    """
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            return GeoIntelData(**data)
        else:
            logger.warning(
                f"Geolocation lookup failed for {ip_address}: {data.get('message')}"
            )
            return None
    except Exception as e:
        logger.error(
            f"An error occurred during geolocation lookup for {ip_address}: {e}"
        )
        return None


async def gather_geo_intel(ip_addresses: List[str]) -> GeoIntelResult:
    """
    Gathers geolocation intelligence for a list of IP addresses.

    Args:
        ip_addresses (List[str]): A list of IP addresses to geolocate.

    Returns:
        GeoIntelResult: A Pydantic model containing the results.
    """
    tasks = [get_geolocation_data(ip) for ip in ip_addresses]
    results = await asyncio.gather(*tasks)
    successful_results = [res for res in results if res]
    return GeoIntelResult(locations=successful_results)


# --- NEW MAPPING FUNCTION ---


def create_ip_map(geo_intel_result: GeoIntelResult, output_path: str):
    """
    Creates an interactive HTML map of geolocated IP addresses using Folium.

    Args:
        geo_intel_result (GeoIntelResult): The result of a geolocation scan.
        output_path (str): The path to save the HTML map file.
    """
    if not geo_intel_result.locations:
        logger.warning("No locations to map.")
        return
    # Find the first valid coordinate to center the map

    map_center = next(
        (
            [loc.lat, loc.lon]
            for loc in geo_intel_result.locations
            if loc.lat is not None and loc.lon is not None
        ),
        [0, 0],
    )  # Default to [0, 0] if no valid coordinates are found

    ip_map = folium.Map(location=map_center, zoom_start=4)

    for loc in geo_intel_result.locations:
        if loc.lat is not None and loc.lon is not None:
            popup_html = f"""
            <b>IP:</b> {loc.query}<br>
            <b>Location:</b> {loc.city}, {loc.country}<br>
            <b>ISP:</b> {loc.isp}
            """
            folium.Marker(
                [loc.lat, loc.lon], popup=folium.Popup(popup_html, max_width=300)
            ).add_to(ip_map)
    ip_map.save(output_path)
    logger.info(f"Successfully generated IP map at: {output_path}")


# --- Typer CLI Application ---


geo_osint_app = typer.Typer()


@geo_osint_app.command("run")
def run_geo_osint_scan(
    ip_addresses: List[str] = typer.Argument(
        ..., help="One or more IP addresses to geolocate."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
    map_file: Optional[str] = typer.Option(
        None, "--map", help="Generate and save an HTML map of the IP addresses."
    ),
):
    """
    Retrieves geolocation information for one or more IP addresses.
    """
    results_model = asyncio.run(gather_geo_intel(ip_addresses))
    results_dict = results_model.model_dump(exclude_none=True)

    target = ip_addresses[0] if ip_addresses else "geo_osint"
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target, module="geo_osint", data=results_dict)

    # If the user provides the --map option, call the new function

    if map_file:
        create_ip_map(results_model, map_file)
    logger.info("Geolocation OSINT scan complete.")
