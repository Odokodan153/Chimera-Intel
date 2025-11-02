"""
Module for Open-Source Data Intelligence (OS-DATAINT).

Provides tools to query and retrieve data from open-source financial
and economic datasets, such as the World Bank Open Data API.
"""

import typer
import logging
from typing import Optional, List
from .schemas import OpenDataResult, WorldBankIndicator
from .http_client import sync_client
from .utils import save_or_print_results
from .database import save_scan_to_db

logger = logging.getLogger(__name__)

# World Bank API details
# Example Indicator: NY.GDP.MKTP.CD (GDP in current US$)
WB_API_BASE_URL = "https://api.worldbank.org/v2"


def get_world_bank_indicator(
    indicator_code: str, country_code: str = "WLD"
) -> OpenDataResult:
    """
    Retrieves data for a specific indicator and country from the World Bank.

    Args:
        indicator_code (str): The official World Bank indicator code (e.g., "NY.GDP.MKTP.CD").
        country_code (str): The ISO 3-letter country code (e.g., "USA", "CHN").
                            Defaults to "WLD" for World.

    Returns:
        OpenDataResult: A Pydantic model with the retrieved data points.
    """
    query_str = f"Indicator: {indicator_code}, Country: {country_code}"
    logger.info(f"Querying World Bank for: {query_str}")

    url = f"{WB_API_BASE_URL}/country/{country_code}/indicator/{indicator_code}"
    params = {
        "format": "json",
        "per_page": 50,  # Get last 50 years/data points
        "date": "1960:2025",
        "MRV": 50, # Most Recent 50 values
    }

    try:
        response = sync_client.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        if not isinstance(data, list) or len(data) < 2 or not data[1]:
            logger.warning(f"No data returned from World Bank for query: {query_str}")
            return OpenDataResult(
                query=query_str,
                total_results=0,
                error="No data found or malformed API response.",
            )

        # The first element data[0] is metadata, data[1] is the list of results
        raw_points = data[1]
        data_points: List[WorldBankIndicator] = []
        for point in raw_points:
            # Adapt the World Bank response to our Pydantic model
            indicator_data = {
                "indicator": point.get("indicator", {}).get("value"),
                "country": point.get("country", {}).get("value"),
                "countryiso3code": point.get("countryiso3code"),
                "date": point.get("date"),
                "value": point.get("value"),
                "unit": point.get("unit"),
                "sourceID": point.get("sourceID"),
                "lastupdated": point.get("lastupdated"),
            }
            data_points.append(WorldBankIndicator.model_validate(indicator_data))

        return OpenDataResult(
            query=query_str,
            total_results=len(data_points),
            data_points=data_points,
        )

    except Exception as e:
        logger.error(f"Failed to query World Bank API: {e}")
        return OpenDataResult(
            query=query_str,
            total_results=0,
            error=f"An API error occurred: {e}",
        )


# --- Typer CLI Application ---

open_data_app = typer.Typer(
    name="open-data", help="Query open-source financial and economic datasets."
)


@open_data_app.command("world-bank")
def run_world_bank_search(
    indicator: str = typer.Argument(
        ..., help="The World Bank indicator code (e.g., NY.GDP.MKTP.CD for GDP)."
    ),
    country: str = typer.Option(
        "WLD",
        "--country",
        "-c",
        help="The 3-letter ISO country code (e.g., USA, CHN, WLD).",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches the World Bank Open Data API for a specific economic indicator.
    """
    results_model = get_world_bank_indicator(indicator, country)
    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)

    db_target = f"{indicator}_{country}"
    save_scan_to_db(target=db_target, module="open_data_world_bank", data=results_dict)