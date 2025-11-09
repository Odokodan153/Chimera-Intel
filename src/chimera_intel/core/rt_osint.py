"""
Real-Time OSINT Monitoring (RT-OSINT) Module.

Monitors clearnet threat feeds and .onion archives via a local Tor proxy
for keywords of journalistic interest. Alerts on new matches.

Based on the user-provided script.
"""

import typer
import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup
from rich import print
from rich.live import Live
from rich.table import Table
from datetime import datetime
import json
import os
from urllib.parse import urljoin

rt_osint_app = typer.Typer()

# Global state for deduplication
SEEN_URLS = set()
DEDUP_FILE = "rt_osint_seen_urls.json"


def load_seen_urls():
    """Loads the set of seen URLs from the deduplication file."""
    if os.path.exists(DEDUP_FILE):
        try:
            with open(DEDUP_FILE, "r") as f:
                return set(json.load(f))
        except json.JSONDecodeError:
            print(f"[yellow]Warning: Could not read deduplication file {DEDUP_FILE}. Starting fresh.[/yellow]")
            return set()
    return set()


def save_seen_urls(urls_set: set):
    """Saves the set of seen URLs to the deduplication file."""
    try:
        with open(DEDUP_FILE, "w") as f:
            json.dump(list(urls_set), f, indent=2)
    except IOError as e:
        print(f"[red]Error saving deduplication file: {e}[/red]")


async def fetch(session: aiohttp.ClientSession, url: str) -> str:
    """Asynchronously fetches text content from a URL."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        async with session.get(url, timeout=20, headers=headers) as resp:
            if resp.status != 200:
                print(f"[yellow]Warning: Received status {resp.status} from {url}[/yellow]")
                return ""
            return await resp.text()
    except asyncio.TimeoutError:
        print(f"[red]Error: Timeout fetching {url}[/red]")
        return ""
    except Exception as e:
        print(f"[red]Error fetching {url}: {e}[/red]")
        return ""


async def check_clearnet(session: aiohttp.ClientSession, keywords: list[str]) -> list:
    """Checks clearnet threat feeds for keywords."""
    results = []
    
    # Define feed URLs and their parsing logic
    feeds = {
        "BleepingComputer": {
            "url": "https://www.bleepingcomputer.com/search/?q={keyword}",
            "base": "https://www.bleepingcomputer.com",
            "selector": "ul#search-results li",
            "title_selector": "h3 a",
            "link_selector": "h3 a",
        },
        "KrebsOnSecurity": {
            "url": "https://krebsonsecurity.com/page/1/?s={keyword}",
            "base": "https://krebsonsecurity.com",
            "selector": "article.post",
            "title_selector": "h2.entry-title a",
            "link_selector": "h2.entry-title a",
        }
    }

    for keyword in keywords:
        for feed_name, config in feeds.items():
            url = config["url"].format(keyword=keyword)
            html = await fetch(session, url)
            if not html:
                continue
            
            soup = BeautifulSoup(html, "html.parser")
            articles = soup.select(config["selector"])
            
            for article in articles[:5]: # Limit to 5 per feed
                title_tag = article.select_one(config["title_selector"])
                link_tag = article.select_one(config["link_selector"])
                
                if title_tag and link_tag:
                    title = title_tag.get_text(strip=True)[:70]
                    href = link_tag.get("href", "")
                    
                    # Ensure URL is absolute
                    if not href.startswith("http"):
                        href = urljoin(config["base"], href)
                        
                    if href and href not in SEEN_URLS:
                        SEEN_URLS.add(href)
                        results.append((f"{feed_name}: {keyword}", title, href))
    return results


async def check_onion(session: aiohttp.ClientSession, keywords: list[str]) -> list:
    """Checks the Ahmia.fi .onion archive for keywords."""
    results = []
    ahmia_url = "https://ahmia.fi" # Use https clearnet version
    
    for keyword in keywords:
        url = f"{ahmia_url}/search/?q={keyword}"
        html = await fetch(session, url)
        if not html:
            continue
            
        soup = BeautifulSoup(html, "html.parser")
        search_results = soup.select("li.result")[:5] # Limit to 5
        
        for r in search_results:
            title_tag = r.find("a")
            onion_url_tag = r.find("cite")
            
            if title_tag and onion_url_tag:
                title = title_tag.text.strip()[:70]
                onion_url = onion_url_tag.text.strip()
                
                if onion_url in SEEN_URLS or "ahmia.fi" in onion_url:
                    continue
                    
                SEEN_URLS.add(onion_url)
                results.append((f"Ahmia: {keyword}", title, onion_url))
    return results


async def perform_checks(proxy_address: str, keywords: list[str], interval: int):
    """The main monitoring loop logic."""
    print(f"Connecting via Tor proxy: [bold]{proxy_address}[/bold]...")
    
    # Setup Tor connector
    connector = None
    try:
        connector = ProxyConnector.from_url(proxy_address)
    except Exception as e:
        print(f"[bold red]Error initializing proxy connector:[/bold red] {e}")
        print("[yellow]Please ensure 'aiohttp_socks' is installed: pip install 'aiohttp[socks]'[/yellow]")
        return
        
    async with aiohttp.ClientSession(connector=connector) as session:
        # Check connection
        try:
            print("Verifying Tor connection...")
            test_resp_text = await fetch(session, "https://check.torproject.org/api/ip")
            test_data = json.loads(test_resp_text)
            if not test_data.get("IsTor"):
                print("[bold red]Connection failed:[/bold red] Not connected to Tor.")
                return
            print(f"[bold green]Tor Connection Verified.[/bold green] Exit IP: {test_data.get('IP')}")
        except Exception as e:
            print(f"[bold red]Tor Connection Error:[/bold red] {e}")
            print("[yellow]Hint: Is your local Tor service (e.g., Tor Browser) running?[/yellow]")
            return

        print(f"\nMonitoring for keywords: [cyan]{', '.join(keywords)}[/cyan]")
        
        # --- Main Monitoring Loop ---
        table = Table(show_header=True, header_style="bold magenta", title="Real-Time OSINT Monitor")
        table.add_column("Timestamp", style="dim", width=20)
        table.add_column("Keyword Match", style="cyan")
        table.add_column("Title / Listing", style="white")
        table.add_column("URL", style="blue")

        with Live(table, refresh_per_second=4, vertical_overflow="visible") as live:
            while True:
                live.update(table, refresh=True)
                clearnet_results = await check_clearnet(session, keywords)
                onion_results = await check_onion(session, keywords)
                all_results = clearnet_results + onion_results

                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if all_results:
                    for row in all_results:
                        table.add_row(now, row[0], row[1], row[2])
                    live.update(table, refresh=True)
                    save_seen_urls(SEEN_URLS)
                else:
                    # Add a status row to show it's still working
                    table.add_row(now, "[dim]Status[/dim]", "[dim]No new results found.[/dim]", "[dim]...[/dim]")
                    live.update(table, refresh=True)

                # Keep table from getting too long
                if len(table.rows) > 20:
                     table.rows = table.rows[-20:]

                try:
                    await asyncio.sleep(interval)
                except asyncio.CancelledError:
                    print("\n[bold]Monitor shutting down...[/bold]")
                    save_seen_urls(SEEN_URLS)
                    break


@rt_osint_app.command(name="monitor")
def monitor(
    keywords: str = typer.Option(
        "cocaine,heroin,meth,AK-47,pistol",
        "--keywords",
        "-k",
        help="Comma-separated keywords to monitor (used if --keyword-file is not provided).",
    ),
    keyword_file: str = typer.Option(
        None,
        "--keyword-file",
        "-f",
        help="Path to a text file containing keywords (one per line). Overrides --keywords.",
    ),
    interval: int = typer.Option(
        300,
        "--interval",
        "-i",
        help="Check interval in seconds.",
    ),
    proxy: str = typer.Option(
        "socks5h://127.0.0.1:9050",
        "--proxy",
        "-p",
        help="SOCKS5 proxy address for your local Tor service.",
    ),
):
    """
    Run the real-time OSINT monitor for drugs and weapons reporting.
    
    This tool monitors public clearnet feeds and .onion archives
    over a Tor connection.
    """
    global SEEN_URLS
    SEEN_URLS = load_seen_urls()
    keyword_list = []

    if keyword_file:
        print(f"[bold]Loading keywords from file: [cyan]{keyword_file}[/cyan]")
        try:
            with open(keyword_file, "r") as f:
                # Read, strip whitespace, filter empty lines and lines starting with #
                keyword_list = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
            if not keyword_list:
                print(f"[bold red]Error: Keyword file '{keyword_file}' is empty or only contains comments.[/bold red]")
                raise typer.Exit(code=1)
        except FileNotFoundError:
            print(f"[bold red]Error: Keyword file not found at '{keyword_file}'[/bold red]")
            raise typer.Exit(code=1)
        except Exception as e:
            print(f"[bold red]Error reading keyword file: {e}[/bold red]")
            raise typer.Exit(code=1)
    else:
        print("[bold]Loading keywords from command line argument.[/bold]")
        keyword_list = [k.strip() for k in keywords.split(",") if k.strip()]

    if not keyword_list:
        print("[bold red]Error: No keywords to monitor.[/bold red]")
        print("[yellow]Hint: Use the '--keywords' option or provide a valid '--keyword-file'.[/yellow]")
        raise typer.Exit(code=1)

    print("[bold cyan]Starting Real-Time OSINT Monitor...[/bold cyan]")
    print("[yellow]Press CTRL+C to stop.[/yellow]")
    
    try:
        asyncio.run(perform_checks(proxy, keyword_list, interval))
    except KeyboardInterrupt:
        print("\n[bold yellow]Stopping monitor...[/bold]")
        save_seen_urls(SEEN_URLS)
        print("[green]Deduplication file saved. Exiting.[/green]")