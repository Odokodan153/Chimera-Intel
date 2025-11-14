"""
Chimera-Intel Active Reconnaissance Module
(Consent-Gated)

Provides non-intrusive active reconnaissance capabilities, gated by user consent.
Includes rate-limiting and safe parsing.
"""

import asyncio
import httpx
import typer
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from .aia_framework import aia_framework 
from .reporter import reporter  
from .user_manager import user_manager  
from .config_loader import ConfigLoader
from .logger_config import setup_logging
from .automation import Playbook
from .utils import console

# --- Configuration ---
logger = setup_logging()
config = ConfigLoader()

USER_AGENT = config.get(
    "active_recon.user_agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
)
MAX_CONCURRENCY = config.get("active_recon.concurrency", 10)
CRAWL_DEPTH = config.get("active_recon.crawl_depth", 2)
REQUEST_TIMEOUT = config.get("active_recon.timeout", 10)

# --- Module-level Globals ---
semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
http_client = httpx.AsyncClient(
    timeout=REQUEST_TIMEOUT,
    follow_redirects=True,
    headers={"User-Agent": USER_AGENT},
    verify=False
)

# Define the Typer app for this module
active_recon_app = typer.Typer()


async def _check_consent(user_id: str, target: str) -> bool:
    """Internal: Verify user consent for active scanning against a target."""
    try:
        consent_granted = await user_manager.check_active_recon_consent(user_id, target)
        if not consent_granted:
            logger.warning(f"Active recon DENIED for target '{target}' by user '{user_id}'. No consent.")
            return False
        logger.info(f"Active recon CONSENT VERIFIED for target '{target}' by user '{user_id}'.")
        return True
    except Exception as e:
        logger.error(f"Error during consent check for {target}: {e}")
        return False

async def _fetch_url(url: str) -> httpx.Response | None:
    """Safely fetches a URL using the module's semaphore and client."""
    async with semaphore:
        try:
            head_resp = await http_client.head(url)
            head_resp.raise_for_status()
            
            if head_resp.status_code < 400 and "text/html" in head_resp.headers.get("content-type", ""):
                 get_resp = await http_client.get(url)
                 get_resp.raise_for_status()
                 return get_resp
            return head_resp

        except httpx.HTTPStatusError as e:
            logger.debug(f"HTTP status error for {url}: {e.response.status_code}")
        except httpx.RequestError as e:
            logger.warning(f"Request error for {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
        return None

async def _safe_crawl(base_url: str, depth: int) -> Set[str]:
    """
    Performs a depth-limited, non-intrusive crawl.
    Uses BeautifulSoup for link extraction.
    """
    logger.info(f"Starting safe crawl for {base_url} (depth={depth})")
    found_links = set()
    to_visit = {base_url}
    visited = set()
    
    for i in range(depth):
        if not to_visit:
            break
        
        current_links_to_visit = list(to_visit)
        to_visit.clear()
        visited.update(current_links_to_visit)
        
        tasks = [asyncio.create_task(_fetch_url(url)) for url in current_links_to_visit]
        results = await asyncio.gather(*tasks)

        for resp in results:
            if resp and "text/html" in resp.headers.get("content-type", ""):
                try:
                    soup = BeautifulSoup(resp.text, "lxml")
                    base_domain = urlparse(str(resp.url)).netloc
                    
                    for link_tag in soup.find_all("a", href=True):
                        href = link_tag["href"]
                        abs_url = urljoin(str(resp.url), href)
                        
                        if urlparse(abs_url).netloc == base_domain:
                            if abs_url not in visited and abs_url not in to_visit:
                                found_links.add(abs_url)
                                to_visit.add(abs_url)
                except Exception as e:
                    logger.warning(f"Error parsing HTML from {resp.url}: {e}")

    logger.info(f"Safe crawl found {len(found_links)} new links.")
    return found_links

async def _enumerate_directories(base_url: str, wordlist: List[str]) -> List[str]:
    """Performs non-intrusive directory enumeration using a safe wordlist."""
    logger.info(f"Starting directory enumeration for {base_url}")
    found_paths = []
    base_url = base_url.rstrip('/')
    
    tasks = []
    for path in wordlist:
        url = f"{base_url}/{path.strip('/')}"
        tasks.append(asyncio.create_task(_fetch_url(url)))

    results = await asyncio.gather(*tasks)

    for res in results:
        if res and res.status_code < 400:
            logger.info(f"Found directory/file: {res.url} (Status: {res.status_code})")
            found_paths.append(str(res.url))
    
    logger.info(f"Directory enumeration found {len(found_paths)} accessible paths.")
    return found_paths

async def _discover_apis(base_url: str) -> Dict[str, Any]:
    """Looks for common API specification files (OpenAPI/Swagger)."""
    logger.info(f"Starting API discovery for {base_url}")
    api_specs = {}
    common_paths = [
        "swagger.json", "openapi.json", "api/swagger.json", "api/openapi.json",
        "v1/swagger.json", "v2/swagger.json", "v3/swagger.json",
        "swagger/v1/swagger.json", "api-docs.json", "swagger-ui.html"
    ]
    
    tasks = []
    for path in common_paths:
        url = f"{base_url.rstrip('/')}/{path}"
        tasks.append(asyncio.create_task(_fetch_url(url)))

    results = await asyncio.gather(*tasks)

    for res in results:
        if res and res.status_code == 200:
            try:
                spec = res.json()
                if isinstance(spec, dict) and ("swagger" in spec or "openapi" in spec):
                    logger.info(f"Found API Spec (JSON) at: {res.url}")
                    api_specs[str(res.url)] = spec
            except Exception:
                if "text/html" in res.headers.get("content-type", ""):
                     logger.info(f"Found potential API UI page at: {res.url}")
                     api_specs[str(res.url)] = "HTML UI Page"
                continue

    return api_specs

async def run_active_recon_playbook(user_id: str, target_domain: str) -> str:
    """
    Executes the full active recon playbook against a target domain.
    This is the primary entry point that is gated by consent.
    """
    logger.info(f"Received request for active recon playbook: User='{user_id}', Target='{target_domain}'")
    target_url = f"https://{target_domain}"
    
    if not await _check_consent(user_id, target_domain):
        return "Active reconnaissance cancelled: User consent not provided or verified."

    console.print(f"[bold cyan]Consent verified.[/bold cyan] Starting active recon playbook for {target_url}...")
    
    safe_wordlist = config.get("active_recon.wordlist", ["admin", "login", "api", "dashboard", "test", "v1", "v2", "config"])
    
    tasks = {
        "crawling": _safe_crawl(target_url, CRAWL_DEPTH),
        "dir_enum": _enumerate_directories(target_url, safe_wordlist),
        "api_discovery": _discover_apis(target_url),
    }
    
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    playbook_results = dict(zip(tasks.keys(), results))
    
    for key, value in playbook_results.items():
        if isinstance(value, Exception):
            logger.error(f"Error in active recon step '{key}': {value}")
            playbook_results[key] = f"Error: {value}"
        elif isinstance(value, set):
            playbook_results[key] = list(value)

    logger.info(f"Active recon playbook completed for {target_url}")

    console.print("[cyan]Sending results to AIA Framework for analysis...[/cyan]")
    aia_prompt = f"Analyze the following active recon results for {target_domain}. Identify key attack vectors, sensitive endpoints, and potential API vulnerabilities. Results: {playbook_results}"
    analysis_report = await aia_framework.generate_analysis(aia_prompt, "active_recon_analysis")
    
    console.print("[cyan]Creating dossier...[/cyan]")
    dossier_data = {
        "target": target_domain,
        "raw_results": playbook_results,
        "aia_analysis": analysis_report,
    }
    
    dossier_id = await reporter.create_dossier(
        title=f"Active Recon Dossier: {target_domain}",
        summary=f"Consent-gated active reconnaissance results and AIA analysis for {target_domain}.",
        data=dossier_data,
        tags=["active-recon", "dossier", target_domain]
    )
    
    logger.info(f"Dossier {dossier_id} created for {target_domain}")
    console.print(f"[bold green]Dossier {dossier_id} created successfully.[/bold green]")
    return dossier_id

def register_active_recon_playbooks():
    """
    Registers the active recon playbooks with the AutomationManager.
    This is called by the plugin's initialize method.
    <<< FIX: This function no longer takes 'manager' as an argument. >>>
    It imports the global instance directly.
    """
    # <<< FIX: Import the global instance here >>>
    from .automation import automation_manager
    
    playbook = Playbook(
        name="run_full_active_recon",
        description="Run the full, consent-gated active recon playbook (crawl, dir enum, API discovery) and generate a dossier.",
        function=run_active_recon_playbook,
        required_params={"user_id": "string", "target_domain": "string"}
    )
    # <<< FIX: Use the imported global instance >>>
    automation_manager.register_playbook(playbook)
    logger.info(f"Playbook '{playbook.name}' registered with AutomationManager.")


# --- CLI Command ---

@active_recon_app.command("run")
def run_cli(
    target_domain: str = typer.Argument(..., help="The target domain to scan (e.g., example.com)"),
    user_id: str = typer.Option(None, help="User ID for consent check. (Defaults to current user)"),
):
    """
    Run the consent-gated active reconnaissance playbook from the CLI.
    """
    console.print(f"[bold]Active Recon Playbook Runner[/bold]")
    
    current_user_id = user_id
    if not current_user_id:
        try:
            current_user = user_manager.get_current_user() 
            if not current_user:
                console.print("[bold red]Error: Could not determine active user. Please use --user-id.[/bold red]")
                raise typer.Exit(code=1)
            current_user_id = current_user.id
            console.print(f"Running as user: [yellow]{current_user.username}[/yellow] (ID: {current_user_id})")
        except Exception as e:
            console.print(f"[bold red]Error getting current user: {e}. Use --user-id.[/bold red]")
            raise typer.Exit(code=1)

    console.print(f"Requesting consent for user [yellow]{current_user_id}[/yellow] to scan [bold red]{target_domain}[/bold red]...")
    
    try:
        dossier_id = asyncio.run(run_active_recon_playbook(current_user_id, target_domain))
        console.print(f"\n[bold green]Playbook complete. Dossier saved: {dossier_id}[/bold green]")
    except Exception as e:
        logger.error(f"CLI run of active recon failed: {e}", exc_info=True)
        console.print(f"\n[bold red]An error occurred: {e}[/bold red]")
        raise typer.Exit(code=1)