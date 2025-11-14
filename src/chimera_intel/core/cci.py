"""
Module for Counter-Counter-Intelligence (CCI) & Attribution Masking.

Provides services for masking platform operations, generating "chaff"
traffic, and self-monitoring for platform exposure.
"""

import typer
import logging
import random
import httpx
import asyncio
from typing import List, Optional, Dict, Any
import aiohttp
from aiohttp_socks import ProxyConnector
from .utils import console
from .config_loader import CONFIG, API_KEYS
from .alert_manager import AlertManager, AlertLevel
from .schemas import AlertLevel
try:
    from .rt_osint import (
        check_clearnet, 
        check_onion, 
        load_seen_urls, 
        save_seen_urls, 
        SEEN_URLS as RT_OSINT_SEEN_URLS
    )
    RT_OSINT_AVAILABLE = True
except ImportError:
    RT_OSINT_AVAILABLE = False
    # Mock functions if rt_osint is not available
    async def check_clearnet(*args): return []
    async def check_onion(*args): return []
    def load_seen_urls(): return set()
    def save_seen_urls(s): pass
    RT_OSINT_SEEN_URLS = set()


logger = logging.getLogger(__name__)

cci_app = typer.Typer(
    name="cci",
    help="Counter-Counter-Intelligence & Attribution Masking operations.",
)

alert_manager = AlertManager()

# --- Cache for chaff generation ---
_plausible_domains_cache: List[str] = []
_domain_cache_lock = asyncio.Lock()


# --- Feature 1: Proxy & UA Services ---
# These functions can be imported by other modules (e.g., http_client.py)
# to mask all platform-initiated requests.

def get_rotating_ua() -> str:
    """
    Returns a random, plausible user-agent from the config pool.
    """
    pool = CONFIG.modules.cci.user_agent_pool
    if not pool:
        logger.warning("CCI user_agent_pool is empty. Using default UA.")
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
    return random.choice(pool)

def _get_proxy_api_key() -> Optional[str]:
    """Helper to retrieve the configured proxy API key from API_KEYS."""
    key_name = CONFIG.modules.cci.proxy_api_key_name
    if not hasattr(API_KEYS, key_name.lower()):
        logger.error(f"CCI proxy_api_key_name '{key_name}' not found in ApiKeys schema.")
        return None
    
    key = getattr(API_KEYS, key_name.lower())
    return key

def get_proxied_http_client(keep_alive: bool = True) -> httpx.Client:
    """
    Returns an httpx.Client configured with a rotating proxy
    (e.g., ScraperAPI, BrightData).
    """
    api_key = _get_proxy_api_key()
    proxy_url_base = CONFIG.modules.cci.proxy_api_url

    if not api_key or not proxy_url_base:
        logger.warning("CCI proxy settings not configured. Using direct connection.")
        return httpx.Client(headers={"User-Agent": get_rotating_ua()})

    # Example for ScraperAPI format: http://scraperapi:APIKEY@proxy-server.scraperapi.com:8001
    # We replace a placeholder like {API_KEY} in the URL
    proxy_url = proxy_url_base.replace("{API_KEY}", api_key)
    
    proxies = {
        "http://": proxy_url,
        "https://": proxy_url,
    }
    
    # Disable keep-alive if not desired (e.g., for max rotation)
    limits = httpx.Limits(max_keepalive_connections=20 if keep_alive else 0)
    
    return httpx.Client(
        proxies=proxies, 
        headers={"User-Agent": get_rotating_ua()}, 
        verify=False, # Proxy managers often require disabling SSL verification
        limits=limits,
        timeout=60.0
    )

def get_proxy_config_for_playwright() -> Optional[Dict[str, Any]]:
    """
    Returns proxy settings for Playwright, if configured.
    """
    api_key = _get_proxy_api_key()
    proxy_url_base = CONFIG.modules.cci.proxy_api_url
    
    if not api_key or not proxy_url_base:
        return None

    # This is highly dependent on the proxy provider.
    # This example parses a ScraperAPI-style URL:
    # "http://scraperapi:{API_KEY}@proxy-server.scraperapi.com:8001"
    try:
        from urllib.parse import urlparse
        parsed = urlparse(proxy_url_base)
        
        return {
            "server": f"{parsed.hostname}:{parsed.port}",
            "username": parsed.username,
            "password": api_key # We assume password is the key
        }
    except Exception as e:
        logger.error(f"Could not parse proxy URL for Playwright: {e}")
        return None

# --- Feature 2: Chaff Generation ---

async def _load_plausible_domains():
    """Internal util to load and cache the majestic million."""
    async with _domain_cache_lock:
        if _plausible_domains_cache:
            return
        
        source_url = CONFIG.modules.cci.chaff_domain_source
        console.print(f"CCI: Loading chaff domain list from {source_url}...")
        try:
            # Use a basic, direct client for this one-off task
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(source_url)
                response.raise_for_status()
            
            lines = response.text.splitlines()
            # Skip header, get domain (e.g., "Rank,Domain,TLD,...")
            count = 0
            for line in lines[1:2001]: # Cache top 2000
                parts = line.split(',')
                if len(parts) > 1:
                    _plausible_domains_cache.append(parts[1])
                    count += 1
            console.print(f"CCI: Loaded {count} plausible domains for chaff generation.")
        except Exception as e:
            console.print(f"[bold red]CCI: Failed to load chaff domains:[/bold red] {e}")

def get_chaff_domains(count: int = 10) -> List[str]:
    """Gets N random domains from the plausible domains cache."""
    if not _plausible_domains_cache:
        logger.error("Chaff domain cache is empty. Cannot generate chaff.")
        return []
    return random.sample(
        _plausible_domains_cache, 
        min(count, len(_plausible_domains_cache))
    )

@cci_app.command("generate-chaff")
async def cli_generate_chaff(
    real_target: str = typer.Argument(
        ..., 
        help="The *real* target (e.g., 'acme.com') to avoid re-querying."
    ),
    count: int = typer.Option(
        10, 
        "--count", "-c", 
        help="Number of chaff queries to generate."
    )
):
    """
    (CCI) Generates background 'chaff' HTTP traffic to mask a real operation.
    
    This command is intended to be called by the AIA framework or an
    automation script *at the same time* as a real scan.
    """
    await _load_plausible_domains()
    chaff_targets = get_chaff_domains(count)
    
    if not chaff_targets:
        console.print("[red]CCI: Cannot generate chaff. No plausible domains loaded.[/red]")
        return

    console.print(f"CCI: Generating {len(chaff_targets)} chaff queries to mask '{real_target}'...")
    
    api_key = _get_proxy_api_key()
    proxy_url_base = CONFIG.modules.cci.proxy_api_url

    if not api_key or not proxy_url_base:
        console.print("[red]CCI: Cannot generate chaff. Proxy settings not configured.[/red]")
        return

    proxy_url = proxy_url_base.replace("{API_KEY}", api_key)
    proxies = {"http://": proxy_url, "https://": proxy_url}
    
    async with httpx.AsyncClient(proxies=proxies, verify=False, timeout=30) as client:
        tasks = []
        for target in chaff_targets:
            if target.lower() == real_target.lower():
                continue
            url = f"https://{target}"
            logger.info(f"CCI Chaff Task: GET {url}")
            tasks.append(client.get(url, headers={"User-Agent": get_rotating_ua()}))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = 0
        for r in results:
            if isinstance(r, httpx.Response) and r.status_code < 500:
                success_count += 1
            elif isinstance(r, Exception):
                logger.debug(f"CCI Chaff request failed: {r}")

        fail_count = len(results) - success_count
        
        console.print(
            f"[bold green]CCI: Chaff generation complete.[/bold green] "
            f"Success/Tolerated: {success_count}, Failed: {fail_count}"
        )

# --- Feature 3: Self-Monitoring ---

@cci_app.command("self-monitor")
async def cli_self_monitor(
    proxy: str = typer.Option(
        "socks5h://127.0.0.1:9050",
        "--proxy",
        "-p",
        help="SOCKS5 proxy address for your local Tor service (for .onion scans).",
    )
):
    """
    (CCI) Scans clearnet and .onion sites for the platform's own assets.
    
    Monitors for keywords defined in `config.modules.cci.self_monitor_assets`.
    Triggers a CRITICAL alert if a new mention is found.
    """
    if not RT_OSINT_AVAILABLE:
        console.print("[red]CCI: Cannot self-monitor. 'rt_osint' module not available.[/red]")
        raise typer.Exit(code=1)

    assets = CONFIG.modules.cci.self_monitor_assets
    if not assets:
        console.print("[yellow]CCI: No self-monitor assets defined in config. Skipping.[/yellow]")
        return

    console.print(f"CCI: Beginning self-monitor for {len(assets)} assets: [cyan]{', '.join(assets)}[/cyan]")
    
    # Use the global SEEN_URLS from rt_osint
    global RT_OSINT_SEEN_URLS
    RT_OSINT_SEEN_URLS = load_seen_urls()
    
    connector = None
    try:
        connector = ProxyConnector.from_url(proxy)
    except Exception as e:
        console.print(f"[bold red]CCI: Could not initialize Tor proxy connector:[/bold red] {e}")
        console.print("[yellow]Hint: Is your local Tor service (e.g., Tor Browser) running?[/yellow]")
        raise typer.Exit(code=1)
        
    async with aiohttp.ClientSession(connector=connector) as session:
        # Check clearnet
        console.print("CCI: Checking clearnet feeds...")
        clearnet_results = await check_clearnet(session, assets)
        
        # Check .onion (Ahmia)
        console.print("CCI: Checking .onion archives...")
        onion_results = await check_onion(session, assets)

    all_results = clearnet_results + onion_results
    
    if not all_results:
        console.print("[green]CCI: Self-monitor complete. No new mentions found.[/green]")
        return

    console.print(f"[bold red]ALERT: Found {len(all_results)} new mentions of platform assets![/bold red]")
    
    for row in all_results:
        keyword, title, url = row
        console.print(f"  - [red]MATCH:[/red] {keyword}")
        console.print(f"  - [red]Title:[/red] {title}")
        console.print(f"  - [red]URL:[/red] {url}")
        
        # Dispatch alert
        alert_manager.dispatch_alert(
            title=f"CCI Self-Monitor Alert: Platform Asset '{keyword}' Found",
            message=f"A new public mention was found: '{title}' at {url}",
            level=AlertLevel.CRITICAL,
            provenance={"module": "cci.self-monitor", "url": url},
            legal_flag="PLATFORM_EXPOSURE_INCIDENT"
        )
    
    save_seen_urls(RT_OSINT_SEEN_URLS)
    console.print("[green]CCI: Self-monitor complete. Critical alerts dispatched.[/green]")