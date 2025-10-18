# --- Sherlock Integration ---
# Sherlock is a powerful library, but it's designed for command-line use.
# We need to import its core components and adapt them for our library.


from sherlock import sherlock, SitesInformation  # type: ignore
from .schemas import SocialProfile, SocialOSINTResult
from .utils import save_or_print_results
from .database import save_scan_to_db
import typer
import logging
import json
from typing import List
import asyncio
import os

logger = logging.getLogger(__name__)


async def find_social_profiles(username: str) -> SocialOSINTResult:
    """
    Finds social media profiles for a given username using the Sherlock library.

    Args:
        username (str): The username to search for across social networks.

    Returns:
        SocialOSINTResult: A Pydantic model containing the list of found profiles.
    """
    logger.info("Starting social media profile search for username: %s", username)

    # Initialize Sherlock's site data
    # The default URL is outdated, so we provide the correct one.

    data_file_path = os.path.join(os.path.dirname(__file__), "resources/data.json")
    site_data = SitesInformation(data_file_path)

    found_profiles: List[SocialProfile] = []
    try:
        # Sherlock's main function is async, so we await it.
        # We pass the username and a list of sites to search.

        results = await sherlock(username, site_data, timeout=10)
        for site, result in results.items():
            if (
                result.get("status")
                and hasattr(result["status"], "name")
                and result["status"].name == "CLAIMED"
            ):
                found_profiles.append(SocialProfile(name=site, url=result["url_user"]))
    except Exception as e:
        logger.error(
            "An error occurred during Sherlock scan for username '%s': %s", username, e
        )
        return SocialOSINTResult(
            username=username,
            found_profiles=[],
            error=f"An error occurred during scan: {e}",
        )
    return SocialOSINTResult(username=username, found_profiles=found_profiles)


# --- Typer CLI Application ---


social_osint_app = typer.Typer()


@social_osint_app.command("run")
def run_social_osint_scan(
    username: str = typer.Argument(
        ..., metavar="USERNAME", help="The username to search for."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    Searches for a username across hundreds of social networks.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    results_model = loop.run_until_complete(find_social_profiles(username))
    results_dict = results_model.model_dump(exclude_none=True)

    if output_file:
        save_or_print_results(results_dict, output_file)
    else:
        typer.echo(json.dumps(results_dict, indent=2))
    save_scan_to_db(target=username, module="social_osint", data=results_dict)
    logger.info("Social media OSINT scan complete for %s", username)
