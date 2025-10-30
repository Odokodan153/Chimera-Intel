import typer
import logging
import asyncio
from typing import Optional, List
from .schemas import AVINTResult, FlightInfo
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .http_client import async_client

logger = logging.getLogger(__name__)

OPENSKY_API_URL = "https://opensky-network.org/api"


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

        from rich.table import Table

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
