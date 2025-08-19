"""
Dark web OSINT module for searching .onion sites.

This module uses the Ahmia search engine to query the dark web for specific terms.
It requires a running Tor proxy (e.g., from the Tor Browser) to route requests
through the Tor network. The client is configured with a SOCKS5 proxy to achieve this.
"""

import typer
import asyncio
import logging
from typing import List
from httpx_socks import AsyncProxyTransport  # type: ignore
from bs4 import BeautifulSoup
import httpx
from .schemas import DarkWebResult, DarkWebScanResult
from .utils import save_or_print_results
from .database import save_scan_to_db

logger = logging.getLogger(__name__)

# Ahmia's .onion address. This can only be accessed via the Tor network.


AHMIA_URL = (
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/"
)


async def search_dark_web(query: str) -> DarkWebScanResult:
    """
    Searches the dark web for a query using the Ahmia search engine via a Tor proxy.

    Args:
        query (str): The search term (e.g., a company name, "leaked passwords").

    Returns:
        DarkWebScanResult: A Pydantic model containing the list of found results.
    """
    logger.info("Starting dark web search for query: %s", query)

    # Configure an httpx client to use the Tor SOCKS5 proxy.
    # This requires the Tor Browser to be running.

    transport = AsyncProxyTransport.from_url("socks5://127.0.0.1:9150")

    found_results: List[DarkWebResult] = []

    try:
        async with asyncio.timeout(60):  # Set a timeout for the entire operation
            async with httpx.AsyncClient(transport=transport) as client:
                response = await client.get(AHMIA_URL, params={"q": query})
                response.raise_for_status()

                soup = BeautifulSoup(response.text, "html.parser")
                results = soup.select("li.result")

                for result in results:
                    title_tag = result.select_one("a")
                    url_tag = result.select_one("cite")
                    desc_tag = result.select_one("p")

                    if title_tag and url_tag:
                        found_results.append(
                            DarkWebResult(
                                title=title_tag.text,
                                url=url_tag.text,
                                description=desc_tag.text if desc_tag else None,
                            )
                        )
    except TimeoutError:
        error_msg = "Search timed out. The Tor network can be slow, or the Tor proxy is not running."
        logger.error(error_msg)
        return DarkWebScanResult(query=query, found_results=[], error=error_msg)
    except Exception as e:
        error_msg = f"An error occurred during dark web scan. Is the Tor Browser running? Error: {e}"
        logger.error(error_msg)
        return DarkWebScanResult(query=query, found_results=[], error=error_msg)
    return DarkWebScanResult(query=query, found_results=found_results)


# --- Typer CLI Application ---


dark_web_app = typer.Typer()


@dark_web_app.command("search")
def run_dark_web_search(
    query: str = typer.Argument(
        ..., help="The search query, e.g., 'mycompany leaked data'"
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches for a query on the dark web via the Ahmia search engine.
    REQUIRES TOR BROWSER TO BE RUNNING.

    Args:
        query (str): The search query, e.g., 'mycompany leaked data'.
        output_file (str): Optional path to save the results to a JSON file.
    """
    results_model = asyncio.run(search_dark_web(query))

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=query, module="dark_web_osint", data=results_dict)
    logger.info("Dark web search complete for query: %s", query)
