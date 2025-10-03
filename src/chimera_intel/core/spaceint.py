import typer
import logging
import asyncio
from typing import Optional, List
from .schemas import SPACEINTResult, TLEData
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .http_client import async_client

logger = logging.getLogger(__name__)

# Real public TLE data source from CelesTrak
CELESTRAK_API_URL = "https://celestrak.org/NORAD/elements/gp.php"


async def track_satellites(norad_id: str) -> SPACEINTResult:
    """
    Retrieves TLE (Two-Line Element) data for a specific satellite from CelesTrak.

    Args:
        norad_id (str): The NORAD ID of a specific satellite (e.g., 25544 for ISS).

    Returns:
        SPACEINTResult: A Pydantic model with the raw TLE data.
    """
    try:
        # Construct the URL to fetch TLE data for the specific NORAD ID
        # FORMAT=tle returns the raw TLE format
        url = f"{CELESTRAK_API_URL}?CATNR={norad_id}&FORMAT=tle"
        
        response = await async_client.get(url)
        response.raise_for_status()
        
        # The response is typically plain text containing the TLE lines
        tle_data_raw = response.text.strip().split('\n')

        if len(tle_data_raw) < 2:
            error_msg = f"CelesTrak returned insufficient TLE data for NORAD ID {norad_id}. Status: {response.status_code}"
            logger.warning(error_msg)
            return SPACEINTResult(total_satellites=0, satellites=[], error=error_msg)
            
        # TLEs are typically 3 lines: Name, Line 1, Line 2.
        # However, the Celestrak endpoint for a single object often omits the name line 
        # when fetching by CATNR, returning only Line 1 and Line 2.
        if len(tle_data_raw) == 3:
             name = tle_data_raw[0].strip()
             line1 = tle_data_raw[1].strip()
             line2 = tle_data_raw[2].strip()
        elif len(tle_data_raw) == 2:
             name = None # Name is often not included for single-object lookup via CATNR
             line1 = tle_data_raw[0].strip()
             line2 = tle_data_raw[1].strip()
        else:
             error_msg = f"CelesTrak returned unexpected TLE format for NORAD ID {norad_id}."
             logger.warning(error_msg)
             return SPACEINTResult(total_satellites=0, satellites=[], error=error_msg)
        
        tle = TLEData(
            norad_id=norad_id,
            name=name,
            line1=line1,
            line2=line2
        )
            
        return SPACEINTResult(total_satellites=1, satellites=[tle])

    except Exception as e:
        logger.error(f"Failed to get satellite data from CelesTrak for NORAD ID {norad_id}: {e}")
        return SPACEINTResult(
            total_satellites=0, satellites=[], error=f"A CelesTrak API error occurred: {e}"
        )


spaceint_app = typer.Typer(help="Space Intelligence (SPACEINT) module.")


@spaceint_app.command("track")
def run_satellite_tracking(
    norad_id: str = typer.Option(
        ..., "--norad-id", help="The NORAD ID of a specific satellite to track. Example: 25544 (ISS)."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save raw TLE data to a JSON file."
    ),
):
    """
    Fetches raw TLE data for a satellite by its NORAD ID for orbital analysis.
    """
    results_model = asyncio.run(track_satellites(norad_id))

    if results_model.error:
        console.print(f"[bold red]Error:[/bold red] {results_model.error}")
        raise typer.Exit(code=1)
        
    console.print(f"\n--- [bold]CelesTrak Satellite TLE Data[/bold] ---\n")
    if results_model.total_satellites > 0:
        tle = results_model.satellites[0]
        name_display = tle.name if tle.name else f"NORAD ID: {tle.norad_id}"
        console.print(f"Tracking Satellite: [cyan]{name_display}[/cyan]")
        
        if output_file:
            results_dict = results_model.model_dump(exclude_none=True)
            save_or_print_results(results_dict, output_file)
            save_scan_to_db(target=norad_id, module="spaceint_tle_tracking", data=results_dict)
        else:
            # Print the raw TLE lines for manual consumption/import
            from rich.panel import Panel
            
            tle_content = f"{tle.line1}\n{tle.line2}"
            
            console.print(Panel(
                tle_content, 
                title=f"Raw TLE for {name_display}",
                border_style="magenta"
            ))
            console.print("\n[yellow]Note:[/yellow] This raw TLE data is the standard input for orbital mechanics libraries.")
    else:
        console.print(f"[bold yellow]Tracking complete:[/bold yellow] No TLE data found for NORAD ID {norad_id}.")