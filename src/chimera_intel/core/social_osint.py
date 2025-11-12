# --- Sherlock Integration ---
# Sherlock is a powerful library, but it's designed for command-line use.
# We need to import its core components and adapt them for our library.


from sherlock import sherlock, SitesInformation  # type: ignore
from .schemas import (
    SocialProfile, 
    SocialOSINTResult,
    TikTokProfile,
    TikTokPost,
    TikTokIntelResult
)
from .utils import save_or_print_results
from .database import save_scan_to_db
import typer
import logging
import json
from typing import List, Optional, Dict, Any
import asyncio
import os
import httpx
from bs4 import BeautifulSoup
import jmespath

logger = logging.getLogger(__name__)

# --- Standard HTTP Client for this module ---
# This client is used by the new TikTok functions.
# It includes a common user-agent to avoid basic blocking.
http_client = httpx.AsyncClient(
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    },
    follow_redirects=True
)
TIKTOK_BASE_URL = "https://www.tiktok.com"

# --- Sherlock (Username Search) Logic ---

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


# --- NEW: TikTok Intelligence Logic ---

def _extract_next_data_json(html_content: str) -> Optional[Dict[str, Any]]:
    """
    Parses the __NEXT_DATA__ JSON blob from TikTok's HTML response.
    
    NOTE: This is the primary method for scraping TikTok and is
    extremely brittle. If TikTok changes their page structure,
    this function will break.
    """
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        script_tag = soup.find("script", id="__NEXT_DATA__")
        
        if not script_tag:
            logger.warning("Could not find __NEXT_DATA__ script tag in HTML.")
            return None
            
        json_data = json.loads(script_tag.string)
        return json_data
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON from __NEXT_DATA__ script tag.")
        return None
    except Exception as e:
        logger.error(f"Error parsing __NEXT_DATA__: {e}")
        return None

async def get_tiktok_profile(username: str) -> TikTokIntelResult:
    """
    Fetches a public TikTok user profile.

    NOTE: This relies on HTML scraping and parsing embedded JSON.
    It is not an official API and may break at any time if
    TikTok changes its website structure.

    Args:
        username: The username of the profile to fetch (without the '@').

    Returns:
        A TikTokIntelResult object containing the profile or an error.
    """
    profile_url = f"{TIKTOK_BASE_URL}/@{username.lstrip('@')}"
    logger.info(f"Attempting to fetch TikTok profile for: {username}")
    
    try:
        response = await http_client.get(profile_url)
        
        if response.status_code == 404:
            logger.warning(f"TikTok profile for '{username}' not found (404).")
            return TikTokIntelResult(query=username, error="Profile not found.")
        
        response.raise_for_status()
        
        json_data = _extract_next_data_json(response.text)
        if not json_data:
            return TikTokIntelResult(query=username, error="Failed to parse profile data from page.")

        # Use JMESPath to navigate the complex nested JSON structure
        # This path targets the user's detailed information
        user_data = jmespath.search("props.pageProps.userInfo.user", json_data)
        
        if not user_data:
            # Fallback path, sometimes the structure differs
            user_data = jmespath.search(
                'props.pageProps."$fragmentRefs"."UserPage-user".user', 
                json_data
            )
            if not user_data:
                logger.error(f"Could not find user data JSON path for '{username}'.")
                return TikTokIntelResult(query=username, error="Could not find user data in page JSON.")

        profile = TikTokProfile.model_validate(user_data)
        return TikTokIntelResult(query=username, profile=profile)

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error fetching profile for '{username}': {e}")
        return TikTokIntelResult(query=username, error=f"HTTP error: {e.status_code}")
    except httpx.RequestError as e:
        logger.error(f"Request error fetching profile for '{username}': {e}")
        return TikTokIntelResult(query=username, error=f"Request error: {str(e)}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while fetching profile '{username}': {e}", exc_info=True)
        return TikTokIntelResult(query=username, error=f"An unexpected error occurred: {str(e)}")


async def get_tiktok_posts_by_hashtag(hashtag: str, count: int = 10) -> TikTokIntelResult:
    """
    Fetches recent public posts for a given hashtag.

    NOTE: This relies on HTML scraping and parsing embedded JSON.
    It is not an official API and may break at any time.

    Args:
        hashtag: The hashtag to search for (without the '#').
        count: The approximate number of posts to return.

    Returns:
        A TikTokIntelResult object containing a list of posts or an error.
    """
    tag_url = f"{TIKTOK_BASE_URL}/tag/{hashtag.lstrip('#')}"
    logger.info(f"Attempting to fetch TikTok posts for hashtag: {hashtag}")

    try:
        response = await http_client.get(tag_url)
        response.raise_for_status()

        json_data = _extract_next_data_json(response.text)
        if not json_data:
            return TikTokIntelResult(query=hashtag, error="Failed to parse hashtag data from page.")

        # Use JMESPath to navigate to the list of video items
        post_items = jmespath.search("props.pageProps.items", json_data)
        
        if post_items is None:
             # Fallback path
            post_items = jmespath.search(
                'props.pageProps."$fragmentRefs"."TagPage-items".itemList', 
                json_data
            )
            if post_items is None:
                logger.warning(f"Could not find post items JSON path for hashtag '{hashtag}'.")
                return TikTokIntelResult(query=hashtag, error="Could not find post items in page JSON.")

        found_posts: List[TikTokPost] = []
        for post_data in post_items[:count]:
            try:
                # The video URL is constructed, not always direct
                post_data['video_url'] = f"{TIKTOK_BASE_URL}/@{post_data['author']['uniqueId']}/video/{post_data['id']}"
                post = TikTokPost.model_validate(post_data)
                found_posts.append(post)
            except Exception as e:
                logger.warning(f"Failed to parse a single post: {e}. Data: {post_data}")
        
        return TikTokIntelResult(query=hashtag, posts=found_posts)

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error fetching posts for hashtag '{hashtag}': {e}")
        return TikTokIntelResult(query=hashtag, error=f"HTTP error: {e.status_code}")
    except httpx.RequestError as e:
        logger.error(f"Request error fetching posts for hashtag '{hashtag}': {e}")
        return TikTokIntelResult(query=hashtag, error=f"Request error: {str(e)}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while fetching hashtag '{hashtag}': {e}", exc_info=True)
        return TikTokIntelResult(query=hashtag, error=f"An unexpected error occurred: {str(e)}")


# --- Typer CLI Application ---
social_osint_app = typer.Typer(
    help="Social media OSINT tools (Sherlock username search and TikTok)."
)


@social_osint_app.command(name="run", help="Search for a username across multiple social media platforms (Sherlock).")
def run_sherlock(
    username: str = typer.Argument(
        ..., metavar="USERNAME", help="The username to search for."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Searches for a username across hundreds of social networks."""
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

    save_scan_to_db(target=username, module="social_osint_sherlock", data=results_dict)
    logger.info("Social media OSINT scan complete for %s", username)


@social_osint_app.command(name="tiktok-profile", help="Get a user's public TikTok profile.")
def run_tiktok_profile(
    username: str = typer.Argument(
        ..., metavar="USERNAME", help="The TikTok username to query (e.g., 'therock')."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Fetches and displays a public TikTok user profile."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    results_model = loop.run_until_complete(get_tiktok_profile(username))
    results_dict = results_model.model_dump(exclude_none=True)

    if output_file:
        save_or_print_results(results_dict, output_file)
    else:
        typer.echo(json.dumps(results_dict, indent=2))

    save_scan_to_db(target=username, module="social_osint_tiktok_profile", data=results_dict)
    logger.info("TikTok profile scan complete for %s", username)


@social_osint_app.command(name="tiktok-hashtag", help="Get recent posts for a public TikTok hashtag.")
def run_tiktok_hashtag(
    hashtag: str = typer.Argument(
        ..., metavar="HASHTAG", help="The TikTok hashtag to query (e.g., 'python')."
    ),
    count: int = typer.Option(
        10, "--count", "-c", help="Number of recent posts to attempt to fetch."
    ),
    output_file: str = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """Fetches and displays recent posts for a public TikTok hashtag."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    results_model = loop.run_until_complete(get_tiktok_posts_by_hashtag(hashtag, count))
    results_dict = results_model.model_dump(exclude_none=True)

    if output_file:
        save_or_print_results(results_dict, output_file)
    else:
        typer.echo(json.dumps(results_dict, indent=2))

    save_scan_to_db(target=hashtag, module="social_osint_tiktok_hashtag", data=results_dict)
    logger.info("TikTok hashtag scan complete for %s", hashtag)