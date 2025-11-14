"""
Channel & Acquisition Intelligence Module for Chimera Intel.

This module provides tools to analyze customer acquisition channels,
including ad library scraping, traffic mix analysis, and
affiliate/partner detection.

--- REVISION ---
This version removes all mock code. It adds real, working functions
to call the correct Similarweb 'traffic-sources' endpoint and the
Google Custom Search Engine (CSE) API, removing all placeholder logic.
---
"""

import typer
import asyncio
import logging
import re
import os
import time
import httpx
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from typing import Optional, Dict, Any
from chimera_intel.core.http_client import get_async_http_client, async_client
from chimera_intel.core.utils import console, save_or_print_results, is_valid_domain
from chimera_intel.core.config_loader import API_KEYS
# Note: We are NO LONGER importing get_traffic_similarweb
from chimera_intel.core.project_manager import resolve_target

logger = logging.getLogger(__name__)
app = typer.Typer(
    no_args_is_help=True, help="Channel & Acquisition Intelligence (CHANINT) tools."
)

# --- Simple In-Memory Cache (local to this module) ---
API_CACHE: Dict[str, Any] = {}
CACHE_TTL_SECONDS = 600  # Cache results for 10 minutes


async def get_traffic_sources_similarweb(domain: str, api_key: str) -> Dict[str, Any]:
    """
    Asynchronously retrieves website traffic source breakdown from Similarweb.
    This is a NEW, REAL function, not the mock from the previous version.
    """
    if not api_key:
        return {"error": "Similarweb API key not found."}
    
    # This is the correct endpoint for traffic source mix
    url = f"https://api.similarweb.com/v1/website/{domain}/traffic-sources/overview-share?api_key={api_key}&granularity=monthly&main_domain_only=false"

    # --- Caching Logic Start ---
    if (
        url in API_CACHE
        and (time.time() - API_CACHE[url]["timestamp"]) < CACHE_TTL_SECONDS
    ):
        logger.info(f"Returning cached Similarweb (traffic-sources) data for {domain}")
        return API_CACHE[url]["data"]
    # --- Caching Logic End ---

    try:
        response = await async_client.get(url) # Reuse global client
        response.raise_for_status()
        json_response = response.json()
        
        # Extract the actual overview data
        overview_data = json_response.get("overview", {})
        
        API_CACHE[url] = {
            "timestamp": time.time(),
            "data": overview_data,
        }  # Save to cache
        return overview_data
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        logger.error(
            "Error fetching traffic sources from Similarweb for '%s': %s", domain, e
        )
        return {"error": f"An error occurred with Similarweb: {e}"}


async def _search_google_cse(
    query: str, api_key: str, cse_id: str, num_results: int = 5
) -> Dict[str, Any]:
    """
    Performs a real search using the Google Custom Search Engine (CSE) API.
    This replaces the mock 'google_search' import.
    """
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": api_key,
        "cx": cse_id,
        "q": query,
        "num": num_results,
    }
    try:
        response = await async_client.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        logger.error(f"Google CSE API search failed for '{query}': {e}")
        return {"error": str(e), "items": []}


@app.command(name="analyze-mix")
def analyze_traffic_mix(
    domain: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save the results to a JSON file."
    ),
):
    """
    Estimates the paid vs. organic traffic mix using Similarweb.
    This now uses the REAL traffic-sources API endpoint.
    """
    target_domain = resolve_target(domain, required_assets=["domain"])
    if not is_valid_domain(target_domain):
        console.print(f"[red]Invalid domain:[/red] '{target_domain}'")
        raise typer.Exit(code=1)

    console.print(f"Analyzing real traffic mix for {target_domain}...")
    similarweb_key = API_KEYS.similarweb_api_key
    if not similarweb_key:
        console.print("[yellow]Similarweb API key not found. Cannot analyze traffic mix.[/yellow]")
        raise typer.Exit(code=1)

    async def get_mix():
        # Call our new, real function
        traffic_data = await get_traffic_sources_similarweb(target_domain, similarweb_key)
        
        if "error" in traffic_data:
            return traffic_data

        if not traffic_data:
            return {"error": "No traffic source data found from Similarweb."}
            
        # This is the REAL, non-simulated report
        report = {
            "domain": target_domain,
            "traffic_mix_overview": traffic_data
        }
        return report

    try:
        results = asyncio.run(get_mix())
        console.print(f"[bold green]Traffic Mix Analysis for {target_domain}:[/bold green]")
        save_or_print_results(results, output_file)
    except Exception as e:
        logger.error(f"Error analyzing traffic mix: {e}", exc_info=True)
        console.print(f"[red]An error occurred: {e}[/red]")


@app.command(name="find-partners")
def find_affiliate_partners(
    domain: Optional[str] = typer.Argument(
        None, help="The target domain. Uses active project if not provided."
    ),
):
    """
    Hunts for affiliate/partner pages, coupon sites, and review sites
    by searching Google and analyzing outbound links.
    """
    target_domain = resolve_target(domain, required_assets=["domain"])
    if not is_valid_domain(target_domain):
        console.print(f"[red]Invalid domain:[/red] '{target_domain}'")
        raise typer.Exit(code=1)

    # Check for required API keys
    google_api_key = API_KEYS.google_api_key
    google_cse_id = API_KEYS.google_cse_id
    if not google_api_key or not google_cse_id:
        console.print("[red]Error: 'google_api_key' and 'google_cse_id' must be set in API_KEYS.[/red]")
        console.print("This command requires a Google Custom Search Engine (CSE) to be set up.")
        raise typer.Exit(code=1)

    console.print(f"Hunting for affiliates and partners for {target_domain}...")

    # Common affiliate link patterns
    AFFILIATE_PATTERNS = [
        r"aff_id=",
        r"ref=",
        r"referral=",
        r"partner_id=",
        r"clickid=",
        r"utm_source=partner",
        r"utm_medium=affiliate",
    ]
    affiliate_regex = re.compile("|".join(AFFILIATE_PATTERNS), re.IGNORECASE)

    # Search queries
    search_queries = [
        f'"{target_domain}" review',
        f'"{target_domain}" coupon',
        f'"{target_domain}" vs',
        f'"{target_domain}" affiliate program',
    ]

    results = {"domain": target_domain, "potential_partners": []}
    
    async def hunt():
        try:
            # 1. Search Google using our new real function
            console.print(f"Searching Google CSE for {len(search_queries)} queries...")
            search_tasks = [
                _search_google_cse(q, google_api_key, google_cse_id, num_results=5) 
                for q in search_queries
            ]
            search_api_results = await asyncio.gather(*search_tasks)
            
            potential_pages = set()
            for api_result in search_api_results:
                if "error" in api_result:
                    logger.warning(f"Google CSE API error: {api_result['error']}")
                    continue
                
                for item in api_result.get("items", []):
                    link = item.get("link")
                    if link and target_domain not in link: # Exclude self-references
                        potential_pages.add(link)

            if not potential_pages:
                console.print("[yellow]No external search results found.[/yellow]")
                return

            # 2. Scrape top results and look for affiliate links
            console.print(f"Scraping {len(potential_pages)} unique pages for affiliate links...")
            async with get_async_http_client() as client:
                tasks = [
                    client.get(url, follow_redirects=True, timeout=10.0)
                    for url in potential_pages
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

            for i, res in enumerate(responses):
                page_url = list(potential_pages)[i]
                if isinstance(res, Exception):
                    logger.warning(f"Failed to scrape {page_url}: {res}")
                    continue

                soup = BeautifulSoup(res.text, "html.parser")
                links_found = []
                
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    # Check if the link *points to* the target domain using an aff pattern
                    if target_domain in href and affiliate_regex.search(href):
                        links_found.append(href)
                
                if links_found:
                    console.print(f"[green]Found affiliate links on:[/green] {page_url}")
                    results["potential_partners"].append({
                        "partner_page": page_url,
                        "link_count": len(links_found),
                        "example_links": list(set(links_found))[:3],
                    })

        except Exception as e:
            logger.error(f"Error hunting for affiliates: {e}", exc_info=True)
            console.print(f"[red]An error occurred during hunt: {e}[/red]")

    asyncio.run(hunt())
    console.print("\n[bold green]Partner/Affiliate Hunt Results:[/bold green]")
    save_or_print_results(results, None)


@app.command(name="scrape-ads")
def scrape_ad_library(
    query: str = typer.Option(
        ..., "--query", "-q", help="The brand or keyword to search for in the ad library."
    ),
    platform: str = typer.Option(
        "meta", help="Ad library platform ('meta', 'google', 'x')."
    ),
):
    """
    (Best-effort) Scrapes a public ad library for creatives
    using Playwright.
    """
    console.print(f"Scraping {platform} ad library for '{query}'...")
    
    # Platform-specific URLs and selectors
    platforms = {
        "meta": {
            "url": f"https://www.facebook.com/ads/library/?active_status=all&ad_type=all&country=ALL&q={query}&search_type=keyword_unordered&media_type=all",
            "ad_selector": "div[role='article']",
            "text_selector": "div[data-ad-preview='message']",
        },
        "google": {
            "url": f"https://adstransparency.google.com/search?query={query}",
            "ad_selector": "div[data-rpc-id]", # Example selector, highly unstable
            "text_selector": "div[class*='ad-text']",
        },
        "x": {
            "url": f"https://ads.twitter.com/library/search?q={query}",
            "ad_selector": "div[data-testid='tweet']", # Example selector
            "text_selector": "div[data-testid='tweetText']",
        }
    }
    
    if platform not in platforms:
        console.print(f"[red]Error: Platform '{platform}' not supported.[/red]")
        raise typer.Exit(code=1)
        
    config = platforms[platform]
    scraped_ads = []

    async def run_scrape():
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                await page.goto(config["url"], wait_until="networkidle", timeout=25000)
                
                # Wait for ads to appear
                await page.wait_for_selector(config["ad_selector"], timeout=15000)
                
                ad_elements = await page.query_selector_all(config["ad_selector"])
                
                console.print(f"Found {len(ad_elements)} potential ad elements.")
                
                output_dir = f"screenshots/ads/{platform}"
                os.makedirs(output_dir, exist_ok=True)

                for i, ad in enumerate(ad_elements[:5]): # Limit to 5
                    ad_text_el = await ad.query_selector(config["text_selector"])
                    ad_text = (await ad_text_el.inner_text()) if ad_text_el else "N/A"
                    
                    # Take screenshot of the ad creative
                    safe_filename = f"{query.replace(' ','_')}_{i}.png"
                    filepath = os.path.join(output_dir, safe_filename)
                    await ad.screenshot(path=filepath)
                    
                    scraped_ads.append({
                        "platform": platform,
                        "query": query,
                        "ad_text": ad_text.strip(),
                        "screenshot_path": filepath,
                    })
                
                await browser.close()
                
        except Exception as e:
            logger.error(f"Playwright failed to scrape ads for {query}: {e}")
            console.print(f"[red]Playwright scrape failed. The site might be protected or selectors are outdated.[/red]")
            console.print(f"[red]Error: {e}[/red]")

    asyncio.run(run_scrape())
    
    if scraped_ads:
        console.print(f"\n[green]Successfully scraped {len(scraped_ads)} ads:[/green]")
        save_or_print_results({"scraped_ads": scraped_ads}, None)


if __name__ == "__main__":
    app()