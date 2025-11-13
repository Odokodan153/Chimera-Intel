"""
OPDEC: Operational Deception & Plausible Deniability Engine

This module acts as a secure proxy and wrapper for other collection
modules (like web_scraper, footprint, etc.). Its goal is to
obfuscate collection activities, generate "noise" to confuse
monitoring services, and use "honey-profiles" to make scraping
less attributable to the platform.
"""

import typer
import logging
import asyncio
import random
from typing import List, Optional, Dict, Any
from sqlalchemy import func
from sqlalchemy.ext.declarative import declarative_base
from .schemas import HoneyProfile

from .utils import console
from .schemas import WebScrapeResult, FootprintResult # Result schemas
from .logger_config import get_logger

# --- Assumed Imports from other Core Modules ---
# We import the "real" functions to wrap them.
try:
    from .database import Base, engine, SessionLocal
    from .http_client import get_http_client
    from .rt_osint import get_proxy_pool
    from .web_scraper import scrape_page as real_scrape_page
    from .footprint import gather_footprint_data as real_gather_footprint
    from .synthetic_media_generator import generate_synthetic_persona
    MODULES_LOADED = True
except ImportError as e:
    MODULES_LOADED = False
    logging.error(f"OPDEC failed to load core dependencies: {e}")
    # Define stubs if modules fail, so the file can be imported
    Base = declarative_base()
    def get_proxy_pool(): return ["http://localhost:8080"]
    def generate_synthetic_persona(): return {"name": "FailedToLoad", "bio": "", "user_agent": ""}
    def get_http_client(proxy=None, headers=None): return None


Base.metadata.create_all(bind=engine)


logger = get_logger(__name__)

app = typer.Typer(
    name="opdec",
    help="Operational Deception & Plausible Deniability Engine.",
)


# --- Feature 1: Traffic Obfuscation ---

def _get_random_proxy() -> Optional[str]:
    """
    Fetches a single random proxy from the real-time OSINT pool.
    """
    if not MODULES_LOADED:
        return None
        
    try:
        pool = get_proxy_pool(min_reliability=0.7)
        if not pool:
            logger.warning("OPDEC: Proxy pool is empty. Falling back to direct connection.")
            return None
        return random.choice(pool)
    except Exception as e:
        logger.error(f"OPDEC: Failed to get proxy pool: {e}")
        return None


# --- Feature 2: "Chaff" Generation ---

def _generate_plausible_target() -> str:
    """Generates a plausible, but fake, target for chaff traffic."""
    # This could be more sophisticated (e.g., pulling from a list
    # of top 1M domains), but this is a simple, effective stub.
    common_words = ["global", "world", "data", "news", "tech", "finance", "media"]
    tld = [".com", ".org", ".net", ".info"]
    return f"{random.choice(common_words)}-{random.randint(1000, 9999)}{random.choice(tld)}"


async def generate_chaff_traffic(chaff_count: int = 10):
    """
    Executes a number of "noise" queries to unrelated domains.
    This is a "fire-and-forget" task.
    """
    if not MODULES_LOADED:
        return
        
    logger.info(f"OPDEC: Generating {chaff_count} chaff requests...")
    tasks = []
    
    for _ in range(chaff_count):
        try:
            target_url = f"https://www.{_generate_plausible_target()}"
            proxy = _get_random_proxy()
            client = get_http_client(proxy=proxy)
            if client:
                # We use the *real* scrape page, as we want the
                # request to be fully executed through the proxy.
                tasks.append(
                    real_scrape_page(client=client, url=target_url)
                )
        except Exception:
            pass # We don't care if chaff fails

    # Run all chaff tasks concurrently and ignore failures
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info(f"OPDEC: Chaff generation complete.")


# --- Feature 3: Honey-Profiles ---

def get_random_honey_profile() -> Optional[HoneyProfile]:
    """Fetches a random honey-profile from the database."""
    try:
        db = SessionLocal()
        profile = db.query(HoneyProfile).order_by(func.random()).first()
        return profile
    except Exception as e:
        logger.error(f"OPDEC: Could not fetch honey-profile: {e}")
        return None
    finally:
        if 'db' in locals():
            db.close()

@app.command("create-profiles", help="Generate and save new honey-profiles.")
def create_honey_profiles(count: int = typer.Option(5, help="Number of profiles to create.")):
    """
    Uses the Synthetic Media Generator to create and store
    fake profiles for scraping.
    """
    if not MODULES_LOADED:
        console.print("[bold red]OPDEC: Core modules not loaded. Cannot create profiles.[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"Generating {count} new honey-profiles...")
    db = SessionLocal()
    try:
        for i in range(count):
            persona = generate_synthetic_persona()
            if not persona or 'name' not in persona:
                console.print(f"[yellow]Skipping profile {i+1}: Failed to generate persona.[/yellow]")
                continue

            profile = HoneyProfile(
                name=persona["name"],
                user_agent=persona.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"),
                bio=persona.get("bio", "")
            )
            db.add(profile)
            console.print(f"  [green]Created:[/green] {profile.name} ({profile.user_agent})")
        
        db.commit()
        console.print(f"\n[bold green]Successfully created {count} profiles.[/bold green]")
    
    except Exception as e:
        db.rollback()
        console.print(f"[bold red]Error creating profiles:[/bold red] {e}")
    finally:
        db.close()


@app.command("list-profiles", help="List available honey-profiles.")
def list_honey_profiles():
    db = SessionLocal()
    try:
        profiles = db.query(HoneyProfile).all()
        if not profiles:
            console.print("[yellow]No honey-profiles found. Use 'create-profiles' to add some.[/yellow]")
            return
            
        console.print(f"[bold cyan]Available Honey-Profiles ({len(profiles)}):[/bold cyan]")
        for profile in profiles:
            console.print(f"- [green]{profile.name}[/green] (ID: {profile.id})")
            console.print(f"  User-Agent: {profile.user_agent[:70]}...")
            
    except Exception as e:
        console.print(f"[bold red]Error listing profiles:[/bold red] {e}")
    finally:
        db.close()


# --- Proxied Collection Functions (The Wrappers) ---

async def proxied_web_scrape(
    url: str,
    use_honey_profile: bool = True,
    generate_chaff: bool = True
) -> WebScrapeResult:
    """
    A wrapper for web_scraper.scrape_page that applies OPDEC.
    
    1.  Spawns "chaff" generation task.
    2.  Picks a random proxy.
    3.  Picks a random honey-profile User-Agent.
    4.  Executes the *real* scrape.
    """
    if not MODULES_LOADED:
        raise Exception("OPDEC dependencies not loaded. Cannot perform proxied scrape.")

    # 1. Spawn chaff generation (fire-and-forget)
    if generate_chaff:
        asyncio.create_task(generate_chaff_traffic(chaff_count=10))

    # 2. Get random proxy
    proxy = _get_random_proxy()
    console.print(f"OPDEC: Routing request for {url} via proxy: {proxy.split('@')[-1] if proxy else 'Direct'}")

    headers = {}
    # 3. Get honey-profile
    if use_honey_profile:
        profile = get_random_honey_profile()
        if profile:
            headers["User-Agent"] = profile.user_agent
            logger.info(f"OPDEC: Using honey-profile '{profile.name}'")

    # 4. Get proxied HTTP client
    client = get_http_client(proxy=proxy, headers=headers)
    if not client:
        raise Exception("OPDEC: Could not initialize HTTP client.")

    # 5. Execute the real scrape
    return await real_scrape_page(client=client, url=url)


async def proxied_gather_footprint(
    target: str,
    generate_chaff: bool = True
) -> FootprintResult:
    """
    A wrapper for footprint.gather_footprint_data that applies OPDEC.
    
    1.  Spawns "chaff" generation task.
    2.  Picks a random proxy.
    3.  Executes the *real* footprint scan.
    """
    if not MODULES_LOADED:
        raise Exception("OPDEC dependencies not loaded. Cannot perform proxied footprint.")

    # 1. Spawn chaff generation (fire-and-forget)
    if generate_chaff:
        asyncio.create_task(generate_chaff_traffic(chaff_count=10))

    # 2. Get random proxy
    proxy = _get_random_proxy()
    console.print(f"OPDEC: Routing footprint for {target} via proxy: {proxy.split('@')[-1] if proxy else 'Direct'}")

    # 3. Get proxied HTTP client
    client = get_http_client(proxy=proxy)
    if not client:
        raise Exception("OPDEC: Could not initialize HTTP client.")

    # 4. Execute the real footprint scan
    # (Assumes the real function is updated to accept the http_client)
    return await real_gather_footprint(domain=target, http_client=client)

# --- CLI Test Command ---

@app.command("test-scrape", help="Run a proxied scrape with chaff and honey-profiles.")
def test_scrape_cli(url: str = typer.Argument("https://httpbin.org/get", help="URL to test scrape.")):
    
    console.print(f"[bold cyan]Running OPDEC-proxied scrape on: {url}[/bold cyan]")
    console.print("Note: This will also spawn 10 background 'chaff' requests.")
    
    try:
        result = asyncio.run(proxied_web_scrape(url))
        
        console.print("\n[bold green]--- Real Request Result ---[/bold green]")
        if result.error:
            console.print(f"[red]Error:[/red] {result.error}")
        else:
            console.print(f"[green]Success:[/green] Fetched {len(result.content)} bytes.")
            # httpbin.org/get returns the headers, so we can check
            if "httpbin.org" in url:
                import json
                try:
                    data = json.loads(result.content)
                    console.print(f"  [cyan]Origin IP:[/cyan] {data.get('origin')}")
                    console.print(f"  [cyan]User-Agent:[/cyan] {data.get('headers', {}).get('User-Agent')}")
                except:
                    pass
    
    except Exception as e:
        console.print(f"[bold red]Failed to run proxied scrape:[/bold red] {e}")