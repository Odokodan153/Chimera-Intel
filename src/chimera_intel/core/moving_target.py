"""
Moving Target Tracking (MOVINT) Module for Chimera Intel.

Fuses AVINT, MARINT, and historical Social OSINT data to track a single entity.
"""

import typer
import asyncio
import logging
import json
import websockets
from typing import Optional, List, Dict, Any
from chimera_intel.core.schemas import (
    AVINTResult,
    FlightInfo,
    SocialOSINTResult,
    SocialProfile,
)
from chimera_intel.core.utils import save_or_print_results, console
from chimera_intel.core.database import save_scan_to_db, get_db_connection
from chimera_intel.core.avint import get_live_flights
from chimera_intel.core.config_loader import API_KEYS
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class FusedLocationPoint(BaseModel):
    source: str
    latitude: float
    longitude: float
    timestamp: str
    velocity: Optional[float] = None
    altitude: Optional[float] = None
    description: str


class MovingTargetResult(BaseModel):
    target_identifier: str
    current_location: Optional[FusedLocationPoint] = None
    historical_track: List[FusedLocationPoint] = []
    error: Optional[str] = None


async def get_vessel_position_once(imo: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Connects to aisstream.io, retrieves the *first* position report for an IMO, and returns it.
    This is a non-streaming version of the MARINT tracker.
    """
    logger.info(f"Attempting single position lookup for IMO: {imo}")
    try:
        async with websockets.connect(
            "wss://stream.aisstream.io/v0/stream", open_timeout=5
        ) as websocket:
            subscribe_message = {
                "APIKey": api_key,
                "FiltersShipIMO": [int(imo)],
                "FilterMessageTypes": ["PositionReport"],
            }
            await websocket.send(json.dumps(subscribe_message))

            # Wait for the first valid message
            async for message_json in websocket:
                message = json.loads(message_json)
                if message["MessageType"] == "PositionReport":
                    position_report = message["Message"]["PositionReport"]
                    if str(position_report.get("ImoNumber")) == imo:
                        logger.info(f"Received position for IMO: {imo}")
                        return position_report
    except Exception as e:
        logger.error(f"Failed to get vessel data for {imo}: {e}")
        return None
    return None


async def get_historical_geotags(username: str) -> List[FusedLocationPoint]:
    """
    Retrieves historical geotagged social media posts from the database.
    """
    logger.info(f"Searching database for historical geotags for: {username}")
    historical_points: List[FusedLocationPoint] = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT scan_data, timestamp FROM scans WHERE target = %s AND module = %s ORDER BY timestamp ASC",
            (username, "social_osint"),
        )
        records = cursor.fetchall()
        conn.close()

        for record in records:
            scan_data = record[0]
            timestamp = record[1].isoformat()
            # This is an invented structure; assumes social_osint results
            # could be enhanced to include 'geotag'
            for profile in scan_data.get("found_profiles", []):
                if profile.get("geotag"):
                    historical_points.append(
                        FusedLocationPoint(
                            source=profile.get("name", "social_media"),
                            latitude=profile["geotag"]["latitude"],
                            longitude=profile["geotag"]["longitude"],
                            timestamp=timestamp,
                            description=f"Geotagged post on {profile.get('name')}",
                        )
                    )
        return historical_points
    except Exception as e:
        logger.error(f"Database error fetching geotags for '{username}': {e}")
        return []


moving_target_app = typer.Typer(
    name="movint",
    help="Moving Target Intelligence (MOVINT). Fuses AVINT, MARINT, and Social OSINT.",
)


@moving_target_app.command("track")
def run_tracking(
    # --- MODIFIED: Removed separate 'identifier' argument ---
    icao24: Optional[str] = typer.Option(
        None, "--icao24", help="The ICAO24 address of a target aircraft."
    ),
    imo: Optional[str] = typer.Option(
        None, "--imo", help="The IMO number of a target vessel."
    ),
    username: Optional[str] = typer.Option(
        None, "--username", help="A social media username to track for geotags."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Fuses live flight, vessel, and historical social media data for a target.
    """
    # --- MODIFIED: Build target identifier from inputs ---
    identifier_parts = []
    if icao24:
        identifier_parts.append(f"icao24={icao24}")
    if imo:
        identifier_parts.append(f"imo={imo}")
    if username:
        identifier_parts.append(f"username={username}")

    if not identifier_parts:
        console.print(
            "[bold red]Error:[/bold red] At least one identifier (--icao24, --imo, or --username) must be provided."
        )
        raise typer.Exit(code=1)

    target_identifier = " AND ".join(identifier_parts)
    # --- END MODIFICATION ---

    console.print(f"--- [bold]Starting Fused Tracking for: {target_identifier}[/bold] ---")
    current_location: Optional[FusedLocationPoint] = None
    historical_track: List[FusedLocationPoint] = []
    error_log: List[str] = []

    async def _run_tasks():
        nonlocal current_location, historical_track, error_log
        tasks = {}
        if icao24:
            tasks["flight"] = get_live_flights(icao24)
        if imo:
            api_key = API_KEYS.aisstream_api_key
            if not api_key:
                error_log.append("AISSTREAM_API_KEY not found.")
            else:
                tasks["vessel"] = get_vessel_position_once(imo, api_key)
        if username:
            tasks["social"] = get_historical_geotags(username)

        results = await asyncio.gather(
            *tasks.values(), return_exceptions=True
        )

        result_map = dict(zip(tasks.keys(), results))

        # Process flight data
        if "flight" in result_map:
            flight_res = result_map["flight"]
            if isinstance(flight_res, AVINTResult) and flight_res.flights:
                flight = flight_res.flights[0]
                current_location = FusedLocationPoint(
                    source="avint",
                    latitude=flight.latitude,
                    longitude=flight.longitude,
                    timestamp=flight.last_contact or "now",
                    velocity=flight.velocity,
                    altitude=flight.baro_altitude,
                    description=f"Aircraft {flight.callsign} ({flight.icao24})",
                )
            elif isinstance(flight_res, Exception):
                error_log.append(f"AVINT Error: {flight_res}")

        # Process vessel data
        if "vessel" in result_map:
            vessel_res = result_map["vessel"]
            if isinstance(vessel_res, dict):
                current_location = FusedLocationPoint(
                    source="marint",
                    latitude=vessel_res["Latitude"],
                    longitude=vessel_res["Longitude"],
                    timestamp=vessel_res.get("Timestamp", "now"),
                    velocity=vessel_res["Sog"],
                    altitude=0,
                    description=f"Vessel IMO {vessel_res['ImoNumber']}",
                )
            elif isinstance(vessel_res, Exception):
                error_log.append(f"MARINT Error: {vessel_res}")

        # Process social data
        if "social" in result_map:
            social_res = result_map["social"]
            if isinstance(social_res, list):
                historical_track.extend(social_res)
            elif isinstance(social_res, Exception):
                error_log.append(f"Social History Error: {social_res}")

    asyncio.run(_run_tasks())

    result_model = MovingTargetResult(
        target_identifier=target_identifier, # Use generated identifier
        current_location=current_location,
        historical_track=historical_track,
        error="; ".join(error_log) if error_log else None,
    )

    results_dict = result_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file, console)
    
    # --- MODIFIED: Use the generated identifier for the database target ---
    save_scan_to_db(
        target=target_identifier, module="moving_target", data=results_dict
    )
    # --- END MODIFICATION ---