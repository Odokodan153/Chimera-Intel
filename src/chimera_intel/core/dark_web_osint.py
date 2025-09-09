"""
Dark web OSINT module for searching .onion sites.

This module uses the Ahmia and Dark Search engines to query the dark web for specific terms.
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
from .config_loader import CONFIG

logger = logging.getLogger(__name__)

# Ahmia's .onion address. This can only be accessed via the Tor network.


AHMIA_URL = (
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/"
)

DARK_SEARCH_URL = "http://darksearch.io/search"


async def search_dark_web_engine(
    query: str, engine: str = "ahmia"
) -> DarkWebScanResult:
    """
    Searches the dark web for a query using a specified search engine via a Tor proxy.

    Args:
        query (str): The search term (e.g., a company name, "leaked passwords").
        engine (str): The search engine to use ('ahmia' or 'darksearch').

    Returns:
        DarkWebScanResult: A Pydantic model containing the list of found results.
    """
    logger.info(f"Starting dark web search on {engine} for query: {query}")

    proxy_url = CONFIG.modules.dark_web.tor_proxy_url
    if not proxy_url:
        error_msg = "Tor proxy URL is not configured in config.yaml."
        logger.error(error_msg)
        return DarkWebScanResult(query=query, found_results=[], error=error_msg)
    transport = AsyncProxyTransport.from_url(proxy_url)

    found_results: List[DarkWebResult] = []

    try:
        async with asyncio.timeout(60):  # Set a timeout for the entire operation
            async with httpx.AsyncClient(transport=transport) as client:
                if engine == "ahmia":
                    response = await client.get(AHMIA_URL, params={"q": query})
                elif engine == "darksearch":
                    response = await client.get(
                        DARK_SEARCH_URL, params={"query": query}
                    )
                else:
                    raise ValueError("Unsupported search engine")
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")

                if engine == "ahmia":
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
                elif engine == "darksearch":
                    results = soup.select("div.card-body")
                    for result in results:
                        title_tag = result.select_one("h5 a")
                        url_tag = result.select_one("h5 small")
                        desc_tag = result.select_one("p.text-break")

                        if title_tag and url_tag:
                            found_results.append(
                                DarkWebResult(
                                    title=title_tag.text.strip(),
                                    url=url_tag.text.strip(),
                                    description=(
                                        desc_tag.text.strip() if desc_tag else None
                                    ),
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
    engine: str = typer.Option(
        "ahmia",
        "--engine",
        "-e",
        help="The search engine to use ('ahmia', 'darksearch').",
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches for a query on the dark web via a selected search engine.
    REQUIRES TOR BROWSER TO BE RUNNING.

    Args:
        query (str): The search query, e.g., 'mycompany leaked data'.
        engine (str): The search engine to use ('ahmia', 'darksearch').
        output_file (str): Optional path to save the results to a JSON file.
    """
    results_model = asyncio.run(search_dark_web_engine(query, engine))

    results_dict = results_model.model_dump(exclude_none=True)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=query, module="dark_web_osint", data=results_dict)
    logger.info("Dark web search complete for query: %s", query)
