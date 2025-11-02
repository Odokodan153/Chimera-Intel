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

from .schemas import (
    GeointReport, 
    CountryRiskProfile, 
    WifiNetworkInfo, 
    WifiGeointResult,
    PhysicalEvent,
    EventDetectionResult,
    AerialVehicleInfo,
    AerialIntelResult,
    ImageryAnalysisRequest,
    DetectedObject,
    ImageryAnalysisResult
)

from .utils import save_or_print_results, console
from .database import get_aggregated_data_for_target, save_scan_to_db
from .http_client import sync_client
from .project_manager import resolve_target
from .geo_osint import get_geolocation_data
from .config_loader import API_KEYS  # Added API_KEYS

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


def find_wifi_networks(
    ssid: Optional[str] = None, lat: Optional[float] = None, lon: Optional[float] = None
) -> WifiGeointResult:
    """
    Searches the WiGLE API for Wi-Fi networks based on location or SSID.
    """
    api_key = API_KEYS.wigle_api_key
    if not api_key:
        return WifiGeointResult(error="WIGLE_API_KEY not found in .env file.")
    if not any([ssid, lat and lon]):
        return WifiGeointResult(
            error="Must provide either an SSID or both latitude and longitude."
        )
    base_url = "https://api.wigle.net/api/v2/network/search"
    headers = {"Authorization": f"Basic {api_key}", "Accept": "application/json"}
    params = {}
    if ssid:
        params["ssid"] = ssid
    if lat and lon:
        params["latrange1"] = lat - 0.01
        params["latrange2"] = lat + 0.01
        params["longrange1"] = lon - 0.01
        params["longrange2"] = lon + 0.01

    try:
        response = sync_client.get(base_url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            return WifiGeointResult(error=data.get("message", "WiGLE API error"))
        networks = [
            WifiNetworkInfo.model_validate(n) for n in data.get("results", [])
        ]
        return WifiGeointResult(networks_found=networks, total_networks=len(networks))
    except Exception as e:
        logger.error(f"Failed to search WiGLE: {e}")
        return WifiGeointResult(error=f"An API error occurred: {e}")


# --- NEW FUNCTION: Event Detection ---

def monitor_physical_events(query: str, domain: Optional[str] = None) -> EventDetectionResult:
    """
    Monitors for physical events (strikes, protests, etc.) related to a target
    using the NewsAPI.
    """
    api_key = API_KEYS.news_api_key
    if not api_key:
        return EventDetectionResult(query=query, error="NEWS_API_KEY not found in .env file.")
        
    search_query = f'"{query}" AND (protest OR strike OR gathering OR "security incident")'
    params = {
        "q": search_query,
        "sortBy": "publishedAt",
        "pageSize": 20,
        "apiKey": api_key,
    }
    if domain:
        params["domains"] = domain

    base_url = "https://newsapi.org/v2/everything"
    
    try:
        response = sync_client.get(base_url, params=params)
        response.raise_for_status()
        data = response.json()
        
        events = []
        for article in data.get("articles", []):
            events.append(
                PhysicalEvent(
                    title=article.get("title"),
                    source_name=article.get("source", {}).get("name"),
                    url=article.get("url"),
                    timestamp=article.get("publishedAt"),
                    summary=article.get("description"),
                )
            )
        return EventDetectionResult(query=query, events_found=events, total_events=len(events))
    except Exception as e:
        logger.error(f"Failed to search NewsAPI for events: {e}")
        return EventDetectionResult(query=query, error=f"An API error occurred: {e}")

# --- NEW FUNCTION: Drone / Aerial Intelligence ---

def find_aerial_vehicles(lat: float, lon: float, radius_km: int = 50) -> AerialIntelResult:
    """
    Integrates open-source UAV/flight tracking data from ADS-B Exchange.
    """
    api_key = API_KEYS.adsbexchange_api_key
    if not api_key:
        return AerialIntelResult(
            query_lat=lat, 
            query_lon=lon, 
            query_radius_km=radius_km, 
            error="ADSBEXCHANGE_API_KEY not found in .env file."
        )
        
    # ADS-B Exchange "v2" API endpoint for aircraft in a circle
    radius_nm = radius_km * 0.539957 # Convert km to nautical miles
    base_url = f"https://adsbexchange.com/api/v2/lat/{lat}/lon/{lon}/dist/{radius_nm}/"
    headers = {"api-key": api_key} # Newer versions require an API key

    try:
        response = sync_client.get(base_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        vehicles = []
        for ac in data.get("ac", []):
            # Try to identify potential drones/UAVs
            # This is difficult; real-world UAVs often don't broadcast on ADS-B.
            # We filter for 'UAV' in type or low altitude / slow speed.
            ac_type = ac.get("t", "N/A")
            is_uav = "UAV" in ac_type.upper() or "DRONE" in ac_type.upper()
            
            # Example filter: low altitude, slow speed, and not a helicopter
            altitude = ac.get("alt_geom", ac.get("alt_baro", 0))
            speed = ac.get("gs", 0)
            if (
                is_uav or 
                (altitude < 2000 and speed < 80 and "HELO" not in ac_type.upper())
            ):
                vehicles.append(
                    AerialVehicleInfo(
                        hex=ac.get("hex", "N/A"),
                        flight=ac.get("flight", "N/A"),
                        lat=ac.get("lat", 0.0),
                        lon=ac.get("lon", 0.0),
                        altitude_ft=altitude,
                        speed_kts=speed,
                        track_deg=ac.get("track", 0),
                        vehicle_type=ac_type,
                    )
                )
                
        return AerialIntelResult(
            query_lat=lat,
            query_lon=lon,
            query_radius_km=radius_km,
            vehicles_found=vehicles,
            total_vehicles=len(vehicles)
        )
    except Exception as e:
        logger.error(f"Failed to search ADS-B Exchange: {e}")
        return AerialIntelResult(
            query_lat=lat, 
            query_lon=lon, 
            query_radius_km=radius_km, 
            error=f"An API error occurred: {e}"
        )


# --- NEW FUNCTION: Planetary-Scale Imagery Analysis (GEOINT++) ---

def analyze_imagery(
    request: ImageryAnalysisRequest, 
    provider: str = "mock"
) -> ImageryAnalysisResult:
    """
    Performs large-scale imagery analysis for change detection, object detection,
    and activity monitoring.
    
    NOTE: This is a mock function. A real implementation would require a dedicated
    backend pipeline integrating with providers like Planet, Maxar, or AWS Open Data
    and running ML models (e.g., YOLO, SAM) at scale.
    """
    logger.info(f"Received imagery analysis request for target: {request.target_geofence_id}")
    
    if not API_KEYS.planet_api_key:
        logger.warning("No PLANET_API_KEY found. Using mock data.")
        provider = "mock"

    if provider == "mock":
        # Simulate finding change and detecting objects
        
        detected_objects = [
            DetectedObject(
                label="Vehicle",
                confidence=0.85,
                lat=request.center_lat + 0.001,
                lon=request.center_lon,
            ),
            DetectedObject(
                label="Storage Tank",
                confidence=0.92,
                lat=request.center_lat,
                lon=request.center_lon + 0.001,
            ),
        ]
        
        return ImageryAnalysisResult(
            request_id=request.request_id,
            status="COMPLETED",
            change_detected=True,
            change_summary="New construction detected in northeast quadrant.",
            objects_detected=detected_objects,
            total_objects=len(detected_objects),
            imagery_provider="Mock Satellite Inc.",
            timestamp_before=datetime(2023, 1, 15).isoformat(),
            timestamp_after=datetime(2023, 2, 15).isoformat(),
        )
    else:
        # Placeholder for real API call
        logger.error(f"Imagery provider '{provider}' not implemented.")
        return ImageryAnalysisResult(
            request_id=request.request_id,
            status="ERROR",
            error=f"Provider '{provider}' not implemented."
        )


# --- END NEW FUNCTION ---


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


@geoint_app.command("wifi-locate")
def run_wifi_geolocation(
    ssid: Optional[str] = typer.Option(
        None, "--ssid", "-s", help="The SSID (network name) to search for."
    ),
    lat: Optional[float] = typer.Option(
        None, "--lat", help="The latitude for the center of the search."
    ),
    lon: Optional[float] = typer.Option(
        None, "--lon", help="The longitude for the center of the search."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Finds Wi-Fi networks using WiGLE to map locations and movement.
    """
    console.print(
        f"[cyan]Searching WiGLE for networks (SSID: {ssid}, Lat: {lat}, Lon: {lon})...[/cyan]"
    )
    results_model = find_wifi_networks(ssid=ssid, lat=lat, lon=lon)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    if ssid:
        save_scan_to_db(target=ssid, module="geoint_wifi_locate", data=results_dict)


# --- NEW COMMAND: Event Detection ---

@geoint_app.command("monitor-events")
def run_event_monitoring(
    target: Optional[str] = typer.Argument(
        None, help="The target company name. Uses active project."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Monitors for physical events (strikes, protests) related to a target.
    """
    target_name = resolve_target(target, required_assets=["company_name"])
    target_domain = resolve_target(target, required_assets=["domain"])

    console.print(f"[cyan]Monitoring for physical events related to: {target_name}...[/cyan]")
    results_model = monitor_physical_events(query=target_name, domain=target_domain)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=target_name, module="geoint_event_monitor", data=results_dict
    )

# --- NEW COMMAND: Aerial Intelligence ---

@geoint_app.command("track-aerial")
def run_aerial_tracking(
    lat: float = typer.Option(..., "--lat", help="Latitude for the center of the search."),
    lon: float = typer.Option(..., "--lon", help="Longitude for the center of the search."),
    radius_km: int = typer.Option(25, "--radius", "-r", help="Search radius in kilometers."),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Finds UAVs / aerial vehicles from open sources (ADS-B) near a location.
    """
    console.print(
        f"[cyan]Searching for aerial vehicles near ({lat}, {lon}) within {radius_km}km...[/cyan]"
    )
    results_model = find_aerial_vehicles(lat=lat, lon=lon, radius_km=radius_km)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=f"{lat},{lon}", module="geoint_aerial_intel", data=results_dict
    )


# --- NEW COMMAND: Planetary-Scale Imagery Analysis (GEOINT++) ---

@geoint_app.command("track-imagery")
def run_imagery_analysis(
    lat: float = typer.Option(..., "--lat", help="Center latitude for the analysis area."),
    lon: float = typer.Option(..., "--lon", help="Center longitude for the analysis area."),
    geofence_id: Optional[str] = typer.Option(
        None, "--geofence", "-g", help="ID of a pre-defined geofence to analyze."
    ),
    target: Optional[str] = typer.Option(
        None, help="Target project to associate this analysis with."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Analyzes satellite imagery for change detection and object monitoring (GEOINT++).
    
    This is a high-level simulation. Real implementation is complex.
    """
    if geofence_id:
        target_name = resolve_target(geofence_id)
        console.print(f"[cyan]Analyzing imagery for geofence: {target_name}...[/cyan]")
        db_target = target_name
    elif target:
        target_name = resolve_target(target)
        console.print(f"[cyan]Analyzing imagery near ({lat}, {lon}) for target: {target_name}...[/cyan]")
        db_target = target_name
    else:
        console.print(f"[cyan]Analyzing imagery for coordinates: ({lat}, {lon})...[/cyan]")
        db_target = f"{lat},{lon}"
        
    
    # In a real app, geofence_id would be used to look up coordinates
    # For now, we just pass the lat/lon and ID
    
    request = ImageryAnalysisRequest(
        target_geofence_id=geofence_id or "adhoc_request",
        center_lat=lat,
        center_lon=lon,
        radius_km=5, # Example default
        analysis_types=["CHANGE_DETECTION", "OBJECT_DETECTION"],
    )
    
    results_model = analyze_imagery(request, provider="mock")
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(
        target=db_target, module="geoint_imagery_analysis", data=results_dict
    )