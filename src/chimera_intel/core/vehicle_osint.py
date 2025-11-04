"""
Vehicle OSINT module for decoding Vehicle Identification Numbers (VINs).

This module uses the U.S. NHTSA (National Highway Traffic Safety Administration)
vPIC API to look up vehicle details. This is a public, free API that
does not require an API key.
"""

import typer
import asyncio
import logging
import httpx
from typing import Optional
from .utils import save_or_print_results, console
from .database import save_scan_to_db
from .project_manager import get_active_project
from .schemas import VehicleScanResult, VehicleInfoResult
logger = logging.getLogger(__name__)

# NHTSA vPIC API URL for decoding VINs
VPIC_API_URL = "https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json"


async def search_vehicle_vin(vin: str) -> VehicleScanResult:
    """
    Looks up a Vehicle Identification Number (VIN) using the NHTSA vPIC API.

    Args:
        vin (str): The 17-character VIN to look up.

    Returns:
        VehicleScanResult: A Pantic model containing the decoded information or an error.
    """
    logger.info(f"Starting VIN lookup for: {vin}")
    
    url = VPIC_API_URL.format(vin=vin)
    
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(url)
            response.raise_for_status()  # Raise an exception for bad status codes
            
            data = response.json()
            
            # The API returns a list in 'Results'
            if not data or "Results" not in data or not data["Results"]:
                raise ValueError("Received empty or invalid response from API.")
                
            result_data = data["Results"][0]
            
            # Check for API-level errors (e.g., invalid VIN)
            if result_data.get("ErrorCode") and result_data["ErrorCode"] != "0":
                error_msg = result_data.get("ErrorText", "Unknown API error.")
                logger.warning(f"API error for VIN {vin}: {error_msg}")
                return VehicleScanResult(
                    query_vin=vin, 
                    info=VehicleInfoResult.model_validate(result_data),
                    error=error_msg
                )

            return VehicleScanResult(
                query_vin=vin,
                info=VehicleInfoResult.model_validate(result_data)
            )
            
    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP error occurred: {e}"
        logger.error(error_msg)
        return VehicleScanResult(query_vin=vin, error=error_msg)
    except asyncio.TimeoutError:
        error_msg = "VIN lookup timed out. The API might be down or slow."
        logger.error(error_msg)
        return VehicleScanResult(query_vin=vin, error=error_msg)
    except Exception as e:
        error_msg = f"An unexpected error occurred during VIN lookup: {e}"
        logger.error(error_msg)
        return VehicleScanResult(query_vin=vin, error=error_msg)


# --- Typer CLI Application ---

vehicle_osint_app = typer.Typer()

@vehicle_osint_app.command("search")
def run_vehicle_search(
    vin: Optional[str] = typer.Argument(
        None,
        help="The 17-character VIN to look up. Uses active project's VIN if not provided.",
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Looks up a Vehicle Identification Number (VIN) for OSINT.
    """
    try:
        asyncio.run(async_run_vehicle_search(vin, output_file))
    except typer.Exit as e:
        raise e


async def async_run_vehicle_search(
    vin: Optional[str],
    output_file: Optional[str],
):
    target_vin = vin
    if not target_vin:
        active_project = get_active_project()
        # Note: Assumes the project schema has a 'vin' or similar field.
        # We'll use 'company_name' as a placeholder if it's a car manufacturer.
        if active_project and active_project.company_name:
            console.print(
                f"[bold yellow]Warning:[/bold yellow] No VIN provided. Using company name '{active_project.company_name}' as a query is not supported for VIN lookup."
            )
            console.print(
                "[bold red]Error:[/bold red] A 17-character VIN is required for this scan."
            )
            raise typer.Exit(code=1)
        else:
            console.print(
                "[bold red]Error:[/bold red] No VIN provided and no active project is set."
            )
            raise typer.Exit(code=1)
            
    if not target_vin or len(target_vin) != 17:
        console.print("[bold red]Error:[/bold red] A valid 17-character VIN is required.")
        raise typer.Exit(code=1)

    results_model = await search_vehicle_vin(target_vin)

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=target_vin, module="vehicle_osint", data=results_dict)
    logger.info("Vehicle VIN lookup complete for: %s", target_vin)