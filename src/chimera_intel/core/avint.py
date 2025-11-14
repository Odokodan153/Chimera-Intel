import typer
import logging
import asyncio
import os  
from typing import Optional, List
from .schemas import AVINTResult, FlightInfo, DroneActivityInfo, DroneActivityResult 
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .http_client import async_client
from rich.table import Table  # +++ MOVED IMPORT TO TOP

logger = logging.getLogger(__name__)

OPENSKY_API_URL = "https://opensky-network.org/api"

ADSBEXCHANGE_API_URL = "https://api.adsb.exchange/v2"


async def get_live_flights(icao24: Optional[str] = None) -> AVINTResult:
    """
    Retrieves live flight data from the OpenSky Network.

    Args:
        icao24 (str, optional): The ICAO24 address of a specific aircraft to track.

    Returns:
        AVINTResult: A Pydantic model with the flight data.
    """
    flights: List[FlightInfo] = []
    try:
        if icao24:
            url = f"{OPENSKY_API_URL}/states/all?icao24={icao24}"
        else:
            url = f"{OPENSKY_API_URL}/states/all"
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()

        for state in data.get("states", []) or []:
            flights.append(
                FlightInfo(
                    icao24=state[0],
                    callsign=state[1].strip() if state[1] else "N/A",
                    origin_country=state[2],
                    longitude=state[5],
                    latitude=state[6],
                    baro_altitude=state[7],
                    on_ground=state[8],
                    velocity=state[9],
                    true_track=state[10],
                    vertical_rate=state[11],
                    geo_altitude=state[13],
                    spi=state[15],
                    position_source=state[16],
                )
            )
        return AVINTResult(total_flights=len(flights), flights=flights)
    except Exception as e:
        logger.error(f"Failed to get live flight data from OpenSky Network: {e}")
        return AVINTResult(
            total_flights=0, flights=[], error=f"An API error occurred: {e}"
        )


# +++ NEW FUNCTION (REAL IMPLEMENTATION) +++
async def monitor_drone_activity(
    lat: float, lon: float, radius_km: float = 5.0
) -> DroneActivityResult:
    """
    Monitors open-source data for drone activity near a location using ADSB-Exchange.
    """
    adsb_api_key = os.getenv("ADSBEXCHANGE_API_KEY")
    if not adsb_api_key:
        return DroneActivityResult(
            location={"lat": lat, "lon": lon, "radius_km": radius_km},
            total_drones=0,
            drones=[],
            error="ADSBEXCHANGE_API_KEY environment variable not set.",
        )
    
    # ADSB-Exchange uses nautical miles
    radius_nm = radius_km * 0.539957
    url = f"{ADSBEXCHANGE_API_URL}/lat/{lat}/lon/{lon}/dist/{radius_nm}/"
    headers = {"Authorization": f"Bearer {adsb_api_key}"}

    logger.info(f"Monitoring drone activity via ADSB-Exchange: {url}")

    try:
        response = await async_client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        detected_drones: List[DroneActivityInfo] = []
        all_aircraft = data.get("ac", [])

        for craft in all_aircraft:
            # Get altitude and speed
            altitude_ft = craft.get("alt_baro", craft.get("alt_geom", 0))
            if altitude_ft == "ground":
                altitude_ft = 0
            
            speed_kts = craft.get("gs", craft.get("tas", 0))
            
            # --- Drone Filtering Logic ---
            is_drone = False
            anomaly_msg = ""

            # 1. Check by ICAO aircraft type
            aircraft_type = craft.get("t", "").upper()
            if "UAS" in aircraft_type or "DRONE" in aircraft_type:
                is_drone = True
                anomaly_msg = "Confirmed UAS type."

            # 2. Check by low/slow profile (common for drones not broadcasting type)
            elif altitude_ft < 1000 and speed_kts < 60 and altitude_ft > 0:
                is_drone = True
                anomaly_msg = "Low-altitude, low-speed profile (suspected UAS)."

            # 3. Check for emergency squawk
            if craft.get("squawk") in ["7600", "7700"]:
                anomaly_msg += f" Emergency Squawk: {craft.get('squawk')}!"
            
            if is_drone:
                detected_drones.append(
                    DroneActivityInfo(
                        hex=craft.get("hex", "N/A"),
                        lat=craft.get("lat", 0.0),
                        lon=craft.get("lon", 0.0),
                        altitude_ft=altitude_ft,
                        speed_kts=speed_kts,
                        track=craft.get("track", 0),
                        registration=craft.get("r"),
                        aircraft_type=aircraft_type,
                        anomaly=anomaly_msg,
                    )
                )

        return DroneActivityResult(
            location={"lat": lat, "lon": lon, "radius_km": radius_km},
            total_drones=len(detected_drones),
            drones=detected_drones,
            error=None,
        )

    except Exception as e:
        logger.error(f"Failed to get drone activity data: {e}")
        return DroneActivityResult(
            location={"lat": lat, "lon": lon, "radius_km": radius_km},
            total_drones=0,
            drones=[],
            error=f"An API error occurred: {e}",
        )


avint_app = typer.Typer()


@avint_app.command("track")
def run_live_tracking(
    icao24: Optional[str] = typer.Option(
        None, "--icao24", help="The ICAO24 address of a specific aircraft."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Tracks live flights, optionally filtering for a specific aircraft.
    """
    results_model = asyncio.run(get_live_flights(icao24))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
    console.print("\n--- [bold]Live Flight Data[/bold] ---\n")
    if icao24:
        console.print(f"Tracking aircraft with ICAO24: {icao24}")
    else:
        console.print(f"Found {results_model.total_flights} live flights.")
    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target = icao24 or "live_flights"
        save_scan_to_db(target=target, module="avint_live_tracking", data=results_dict)
    else:
        # Print a summary table to the console
        table = Table(title="Live Flight Information")
        table.add_column("Callsign", style="cyan")
        table.add_column("Origin Country")
        table.add_column("On Ground", style="yellow")
        table.add_column("Velocity (m/s)")
        table.add_column("Altitude (m)")
        for flight in results_model.flights[:20]:  # Limit console output
            table.add_row(
                flight.callsign,
                flight.origin_country,
                str(flight.on_ground),
                f"{flight.velocity:.2f}" if flight.velocity else "N/A",
                f"{flight.baro_altitude:.0f}" if flight.baro_altitude else "N/A",
            )
        console.print(table)


# +++ NEW COMMAND (USING REAL FUNCTION) +++
@avint_app.command("drone-monitor")
def run_drone_monitoring(
    location: str = typer.Argument(
        ..., help="The latitude and longitude (lat,lon) of the location to monitor."
    ),
    radius_km: float = typer.Option(
        5.0, "--radius", "-r", help="Radius in kilometers to monitor."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Monitors open-source data for drone activity near a location.
    """
    try:
        lat_str, lon_str = location.split(",")
        lat = float(lat_str)
        lon = float(lon_str)
    except ValueError:
        console.print(
            "[bold red]Error:[/bold red] Invalid location format. "
            "Please use 'latitude,longitude' (e.g., '40.7128,-74.0060')."
        )
        raise typer.Exit(code=1)

    results_model = asyncio.run(monitor_drone_activity(lat, lon, radius_km))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n--- [bold]Drone Activity Monitor: ({lat}, {lon}) @ {radius_km}km[/bold] ---\n"
    )
    total_drones = results_model.total_drones
    
    if total_drones == 0:
        console.print(f"[green]No suspected drone activity detected in the specified area.[/green]")
        return

    if output_file:
        results_dict = results_model.model_dump(exclude_none=True)
        save_or_print_results(results_dict, output_file)
        target = f"drone_monitor_{lat}_{lon}"
        save_scan_to_db(target=target, module="avint_drone_monitor", data=results_dict)
    else:
        table = Table(title=f"Detected Suspected Drones ({total_drones})")
        table.add_column("Hex/ID", style="cyan")
        table.add_column("Type")
        table.add_column("Altitude (ft)", style="yellow")
        table.add_column("Speed (kts)")
        table.add_column("Registration")
        table.add_column("Anomaly", style="red")

        for drone in results_model.drones:
            table.add_row(
                drone.hex,
                drone.aircraft_type or "N/A",
                str(drone.altitude_ft),
                str(drone.speed_kts),
                drone.registration or "N/A",
                drone.anomaly or "None",
            )
        console.print(table)