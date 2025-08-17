import typer
import asyncio
from httpx import RequestError, HTTPStatusError
from rich.panel import Panel
import logging
from typing import Dict, List
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.database import save_scan_to_db
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.schemas import (
    WebAnalysisResult,
    WebAnalysisData,
    TechStackReport,
    ScoredResult,
)
from chimera_intel.core.http_client import async_client

# Get a logger instance for this specific file


logger = logging.getLogger(__name__)

# --- Asynchronous Data Gathering Functions ---


async def get_tech_stack_builtwith(domain: str, api_key: str) -> list:
    """
    Asynchronously retrieves website technology stack from the BuiltWith API.

    Args:
        domain (str): The domain to analyze.
        api_key (str): The BuiltWith API key.

    Returns:
        list: A list of unique technology names found.
    """
    if not api_key:
        logger.warning("BuiltWith API key not found. Skipping.")
        return []
    url = f"https://api.builtwith.com/v21/api.json?KEY={api_key}&LOOKUP={domain}"
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        data = response.json()
        technologies = []
        if "Results" in data and data["Results"]:
            for result in data["Results"]:
                for path in result.get("Result", {}).get("Paths", []):
                    for tech in path.get("Technologies", []):
                        technologies.append(tech.get("Name"))
        return list(set(technologies))
    except (HTTPStatusError, RequestError) as e:
        logger.error("Error fetching tech stack from BuiltWith for '%s': %s", domain, e)
        return []


async def get_tech_stack_wappalyzer(domain: str, api_key: str) -> list:
    """
    Asynchronously retrieves website technology stack from the Wappalyzer API.

    Args:
        domain (str): The domain to analyze.
        api_key (str): The Wappalyzer API key.

    Returns:
        list: A list of unique technology names found.
    """
    if not api_key:
        logger.warning("Wappalyzer API key not found. Skipping.")
        return []
    url = f"https://api.wappalyzer.com/v2/lookup/?urls=https://{domain}"
    headers = {"x-api-key": api_key}
    try:
        response = await async_client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        technologies = []
        if data and isinstance(data, list):
            for tech_info in data[0].get("technologies", []):
                technologies.append(tech_info.get("name"))
        return list(set(technologies))
    except (HTTPStatusError, RequestError) as e:
        logger.error(
            "Error fetching tech stack from Wappalyzer for '%s': %s", domain, e
        )
        return []


async def get_traffic_similarweb(domain: str, api_key: str) -> dict:
    """
    Asynchronously retrieves estimated website traffic from the Similarweb API.

    Args:
        domain (str): The domain to analyze.
        api_key (str): The Similarweb API key.

    Returns:
        dict: The API response containing traffic data, or an error.
    """
    if not api_key:
        return {"error": "Similarweb API key not found."}
    url = f"https://api.similarweb.com/v1/website/{domain}/total-traffic-and-engagement/visits?api_key={api_key}&granularity=monthly&main_domain_only=false"
    try:
        response = await async_client.get(url)
        response.raise_for_status()
        return response.json()
    except (HTTPStatusError, RequestError) as e:
        logger.error(
            "Error fetching traffic data from Similarweb for '%s': %s", domain, e
        )
        return {"error": f"An error occurred with Similarweb: {e}"}


# --- Core Logic Function ---


async def gather_web_analysis_data(domain: str) -> WebAnalysisResult:
    """
    The core logic for gathering all web analysis data.

    Args:
        domain (str): The domain to perform the web analysis on.

    Returns:
        WebAnalysisResult: A Pydantic model containing all gathered web analysis data.
    """
    builtwith_key = API_KEYS.builtwith_api_key
    wappalyzer_key = API_KEYS.wappalyzer_api_key
    similarweb_key = API_KEYS.similarweb_api_key
    available_tech_sources = sum(1 for key in [builtwith_key, wappalyzer_key] if key)

    tasks = [
        (
            get_tech_stack_builtwith(domain, builtwith_key)
            if builtwith_key
            else asyncio.sleep(0, result=[])
        ),
        (
            get_tech_stack_wappalyzer(domain, wappalyzer_key)
            if wappalyzer_key
            else asyncio.sleep(0, result=[])
        ),
        (
            get_traffic_similarweb(domain, similarweb_key)
            if similarweb_key
            else asyncio.sleep(0, result={})
        ),
    ]
    builtwith_tech, wappalyzer_tech, traffic_info = await asyncio.gather(*tasks)

    all_tech: Dict[str, List[str]] = {}
    for tech in builtwith_tech:
        all_tech.setdefault(tech, []).append("BuiltWith")
    for tech in wappalyzer_tech:
        all_tech.setdefault(tech, []).append("Wappalyzer")
    scored_tech_results = [
        ScoredResult(
            technology=tech,
            sources=sources,
            confidence=f"{'HIGH' if available_tech_sources > 1 and len(sources) == available_tech_sources else 'LOW'} ({len(sources)}/{available_tech_sources} sources)",
        )
        for tech, sources in sorted(all_tech.items())
    ]

    tech_stack_report = TechStackReport(
        total_unique=len(scored_tech_results), results=scored_tech_results
    )

    web_analysis_data = WebAnalysisData(
        tech_stack=tech_stack_report,
        traffic_info=traffic_info if isinstance(traffic_info, dict) else {},
    )

    return WebAnalysisResult(domain=domain, web_analysis=web_analysis_data)


# --- Typer CLI Application ---


web_app = typer.Typer()


@web_app.command("run")
def run_web_analysis(
    domain: str = typer.Argument(..., help="The target domain to analyze."),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """Analyzes web-specific data asynchronously."""
    if not is_valid_domain(domain):
        logger.warning("Invalid domain format provided to 'web' command: %s", domain)
        console.print(
            Panel(
                f"[bold red]Invalid Input:[/] '{domain}' is not a valid domain format.",
                title="Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    logger.info("Starting asynchronous web analysis for %s", domain)

    results_model = asyncio.run(gather_web_analysis_data(domain))
    results_dict = results_model.model_dump()

    logger.info("Web analysis complete for %s", domain)
    save_or_print_results(results_dict, output_file)
    save_scan_to_db(target=domain, module="web_analyzer", data=results_dict)
