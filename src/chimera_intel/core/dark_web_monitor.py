"""
Continuous Dark Web Monitoring Module for Chimera Intel.

---
Security and OSINT Best Practices (as per user feedback):
1. Do not use this code for illegal activity.
2. Store captured HTML files in a secure location with restricted access.
3. Periodically rotate the Tor identity (using Stem) if making frequent
   requests to avoid being blocked.
4. (Recommendation) Handle signals (SIGINT, SIGTERM) gracefully
   (likely in the main daemon) to cancel pending async tasks.
---
"""

import typer
from typing import Annotated
import httpx
from bs4 import BeautifulSoup
import datetime
import os
from rich.console import Console
from urllib.parse import urlparse, urljoin
import logging
import re
import asyncio
import socket  # 1. Added for Tor daemon check
from chimera_intel.core.config_loader import CONFIG
from chimera_intel.core.http_client import get_async_http_client
from chimera_intel.core.scheduler import add_job
from chimera_intel.core.utils import send_slack_notification, send_teams_notification

# 2. Configure file logging as per recommendation
# This basic config will log to a file.
# Note: This might be overridden by a central logging config if one exists.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("dark_web_monitor.log"),
        logging.StreamHandler(), # Also log to console/stderr
    ],
    force=True, # Ensure this config takes precedence if root is already set
)

console = Console()
logger = logging.getLogger(__name__)

# (REAL) URL for a well-known .onion directory
AHMIA_URL = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/"


# 3. ADDED: Tor daemon availability check
def is_tor_running(default_host="127.0.0.1", default_port=9050) -> bool:
    """Checks if the Tor SOCKS proxy is running."""
    host = default_host
    port = default_port

    # Attempt to extract host/port from config
    try:
        proxy_url = CONFIG.modules.dark_web.tor_proxy_url
        if proxy_url:
            # e.g., "socks5h://127.0.0.1:9050"
            parsed = urlparse(proxy_url)
            host = parsed.hostname or host
            port = parsed.port or port
    except Exception as e:
        logger.warning(f"Could not parse Tor proxy from config, using defaults. Error: {e}")

    try:
        with socket.create_connection((host, port), timeout=5):
            logger.info(f"Tor daemon check successful at {host}:{port}")
            return True
    except OSError as e:
        logger.error(f"Tor daemon check failed for {host}:{port}: {e}")
        return False


async def get_dark_web_targets() -> list[str]:
    """
    (REAL) Fetches a list of dark web targets by scraping a
    public directory (.onion sites) via the Tor proxy.
    """
    console.print(
        f"  - [cyan]Fetching dynamic .onion targets from directory...[/cyan]"
    )
    tor_proxy = CONFIG.modules.dark_web.tor_proxy_url
    if not tor_proxy:
        logger.warning("Tor proxy not configured. Cannot fetch dark web targets.")
        return []

    target_list = []

    # Use 'all://' and socks5h for proper .onion DNS resolution via Tor.
    proxies = {"all://": tor_proxy}

    async with get_async_http_client(proxies=proxies) as client:
        try:
            # Scrape the front page of a directory like Ahmia
            response = await client.get(AHMIA_URL, timeout=30.0)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            # Find links that appear to be .onion sites
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if ".onion" in href:
                    # Clean up the URL
                    url = urljoin(AHMIA_URL, href)
                    parsed_url = urlparse(url)
                    # Rebuild to ensure it's just scheme + netloc
                    onion_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    if onion_url not in target_list:
                        target_list.append(onion_url)

            if not target_list:
                logger.warning(
                    "Scraping Ahmia yielded no .onion links. Using fallback."
                )
                # Add a few known sites as a fallback in case scraping fails
                target_list.append(
                    "http://breachedu76kdyavc64t2yb57d42j3634d52nk37f37454s67sk2d.onion/"
                )
                target_list.append(
                    "http://lockbitapt6vx57t3eeqjofwgcglmutr3i353o2lukb2dlj55x7xid.onion/"
                )

            return target_list

        except Exception as e:
            logger.error(f"Failed to fetch dynamic dark web targets: {e}")
            return []  # Return empty list on failure


async def fetch_site(
    client: httpx.AsyncClient, url: str, keywords: list[str]
):
    """
    Helper function for asyncio.gather to fetch and process a single site.
    """
    try:
        response = await client.get(url, timeout=30.0)
        response.raise_for_status()
        
        # 4. ADDED: Keyword and page text normalization
        soup = BeautifulSoup(response.text, "html.parser")
        page_text = soup.get_text().casefold()

        for keyword in keywords:
            keyword_clean = keyword.strip().casefold()
            if keyword_clean in page_text:
                console.print(
                    f"[bold green]Keyword '{keyword_clean}' found at {url}[/bold green]"
                )
                logger.info(f"Keyword '{keyword_clean}' found at {url}")

                # Save the page for analysis
                if not os.path.exists("dark_web_captures"):
                    os.makedirs("dark_web_captures")
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

                # Sanitize keyword for safe filenames (from previous feedback)
                safe_keyword = re.sub(r"[^a-zA-Z0-9_-]", "_", keyword_clean)
                filename = f"dark_web_captures/capture_{safe_keyword}_{timestamp}.html"

                with open(filename, "w", encoding="utf-8") as f:
                    f.write(response.text)

                # Send notifications
                message = f"🚨 Chimera Intel Alert: Keyword '{keyword_clean}' detected on the dark web at {url}. Page content saved to '{filename}'."
                if (
                    CONFIG.notifications
                    and CONFIG.notifications.slack_webhook_url
                ):
                    send_slack_notification(
                        CONFIG.notifications.slack_webhook_url, message
                    )
                if (
                    CONFIG.notifications
                    and CONFIG.notifications.teams_webhook_url
                ):
                    send_teams_notification(
                        CONFIG.notifications.teams_webhook_url,
                        f"Chimera Intel Alert: Keyword '{keyword_clean}' detected",
                        message,
                    )
    # Expanded exception handling (from previous feedback)
    except (
        httpx.RequestError,
        httpx.ConnectError,
        httpx.TimeoutException,
    ) as e:
        logger.warning(f"Could not connect to {url}. Error: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred for {url}: {e}")


async def run_dark_web_monitor(keywords: list[str]):
    """
    The core function that runs as a scheduled job. It scrapes target sites
    for keywords and sends notifications if found.
    """
    console.print(
        f"[{datetime.datetime.now()}] Running Dark Web Monitor for keywords: {keywords}"
    )

    # 3. ADDED: Check if Tor is running before starting
    if not is_tor_running():
        console.print(
            "[bold red]Error:[/bold red] Tor daemon not running or not accessible on proxy URL. Aborting job."
        )
        return

    tor_proxy = CONFIG.modules.dark_web.tor_proxy_url
    if not tor_proxy:
        # This check is slightly redundant with is_tor_running, but good failsafe
        console.print(
            "[bold red]Error:[/bold red] Tor proxy URL is not configured in config.yaml."
        )
        return

    # (REAL) Fetch targets live instead of using a simulated feed
    dark_web_targets = await get_dark_web_targets()
    if not dark_web_targets:
        console.print(
            "[bold red]Error:[/bold red] Could not fetch any dark web targets to monitor."
        )
        return

    console.print(
        f"  - [cyan]Loaded {len(dark_web_targets)} targets from live directory.[/cyan]"
    )

    # Use 'all://' and socks5h (from previous feedback)
    proxies = {"all://": tor_proxy}

    async with get_async_http_client(proxies=proxies) as client:
        # 5. ADDED: Semaphore for rate limiting concurrent requests
        sem = asyncio.Semaphore(5)  # Limit to 5 concurrent requests

        console.print(
            f"  - [cyan]Scanning {len(dark_web_targets)} sites (5 concurrently)...[/cyan]"
        )

        # Helper to wrap task with semaphore
        async def fetch_with_semaphore(url):
            async with sem:
                await fetch_site(client, url, keywords)

        tasks = [
            fetch_with_semaphore(url) for url in dark_web_targets
        ]
        
        # Run tasks concurrently (from previous feedback)
        await asyncio.gather(*tasks)
        console.print(f"  - [cyan]Dark web scan complete.[/cyan]")


# Create a Typer app for the dark web monitoring commands

dark_web_monitor_app = typer.Typer(
    name="dark-monitor",
    help="Continuous Dark Web Monitoring (Counter-Intelligence)",
)


@dark_web_monitor_app.command(
    "add", help="Add a new dark web monitoring job to the scheduler."
)
def add_dark_web_monitor(
    keywords: Annotated[
        str,
        typer.Option(
            ...,
            "--keywords",
            "-k",
            help="Comma-separated list of keywords to monitor (e.g., 'mycompany.com,internal-api').",
        ),
    ],
    schedule: Annotated[
        str,
        typer.Option(
            ...,
            "--schedule",
            "-s",
            help="Cron-style schedule for the monitor (e.g., '0 * * * *' for hourly).",
        ),
    ],
):
    """
    Schedules a recurring job to monitor dark web sites for specific keywords.
    """
    keyword_list = [k.strip() for k in keywords.split(",")]
    job_id = f"dark_web_monitor_{'_'.join(keyword_list)}"

    add_job(
        func=run_dark_web_monitor,
        trigger="cron",
        cron_schedule=schedule,
        job_id=job_id,
        kwargs={"keywords": keyword_list},
    )
    console.print(
        "[bold green]✅ Successfully scheduled dark web monitor.[/bold green]"
    )
    console.print(f"   - Job ID: {job_id}")
    console.print(f"   - Keywords: {keyword_list}")
    console.print(f"   - Schedule: {schedule}")
    console.print(
        "\nEnsure the Chimera daemon is running for the job to execute: [bold]chimera daemon start[/bold]"
    )