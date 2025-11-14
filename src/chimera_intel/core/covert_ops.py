"""
Covert Digital Operations Module for Chimera Intel.

Provides functionality for:
- Hidden API / Content Enumeration
- Infrastructure Takeover Checks
"""

import typer
import httpx
import asyncio
import dns.resolver
import dns.exception
from typing_extensions import Annotated
from typing import Set
from rich.table import Table
from .database import store_data
from .http_client import get_async_http_client  
from .utils import console

covert_ops_app = typer.Typer(
    name="covert-ops",
    help="Covert Digital Ops: API enumeration and takeover checks.",
)

# A small list of common paths to check for demonstration
COMMON_PATHS = [
    "/admin",
    "/login",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/dashboard",
    "/.git/config",
    "/.env",
    "/.env.production",
    "/.env.local",
    "/backup.zip",
    "/backup.sql",
    "/swagger-ui.html",
    "/swagger.json",
    "/openapi.json",
]

# Common CNAMEs that might be hijackable if misconfigured
# This list is still used, but the check against it is real.
TAKEOVER_PATTERNS = {
    "s3.amazonaws.com": "Amazon S3",
    "github.io": "GitHub Pages",
    "sites.github.com": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "pantheonsite.io": "Pantheon",
    "domains.squarespace.com": "Squarespace",
    "unbouncepages.com": "Unbounce",
    "c.storage.googleapis.com": "Google Cloud Storage",
    ".azurewebsites.net": "Azure App Service",
    # A generic pattern for unclaimed services
    "unclaimed": "Possible Unclaimed Service",
}


async def check_path(
    client: httpx.AsyncClient, base_url: str, path: str
) -> tuple[str, int] | None:
    """
    (REAL) Checks a single path using a HEAD request.
    """
    url = f"{base_url.rstrip('/')}{path}"
    try:
        response = await client.head(url, timeout=10, follow_redirects=False)
        
        # Report common "found" codes (2xx, 3xx, 401, 403)
        # We ignore 404 Not Found.
        if response.status_code < 404:
            return (url, response.status_code)
        
    except httpx.RequestError as e:
        console.print(f"[dim]Error checking {url}: {e}[/dim]", style="dim")
    return None


@covert_ops_app.command(
    name="find-hidden-content",
    help="Find hidden API endpoints and unlinked directories.",
)
async def find_hidden_content(
    target: Annotated[
        str,
        typer.Argument(
            help="The target domain to scan (e.g., 'example.com')."
        ),
    ],
):
    """
    (REAL) Searches for hidden endpoints and directories by checking
    a predefined list of common sensitive paths.
    """
    console.print(f"[bold cyan]Starting hidden content scan on: {target}[/bold cyan]")
    base_url = f"https://{target}"
    
    tasks = []
    results = []
    
    with console.status("[cyan]Scanning common paths...[/cyan]"):
        async with get_async_http_client() as client:
            for path in COMMON_PATHS:
                tasks.append(check_path(client, base_url, path))
            
            # Run checks in parallel
            scan_results = await asyncio.gather(*tasks)
            results = [r for r in scan_results if r is not None]

    if not results:
        console.print("[green]No sensitive hidden paths found from common list.[/green]")
        return

    table = Table(title="[bold yellow]Discovered Content[/bold yellow]")
    table.add_column("URL", style="cyan")
    table.add_column("Status Code", style="magenta")

    module_data = []
    for url, status in results:
        table.add_row(url, str(status))
        module_data.append({"url": url, "status": status})

    console.print(table)
    
    # Store results in database
    try:
        store_data(
            target,
            "covert_ops_content",
            {"discovered_paths": module_data},
        )
        console.print(f"Stored {len(module_data)} findings in database.")
    except Exception as e:
        console.print(f"[red]Error saving to database:[/red] {e}")


async def get_subdomains_for_takeover(target: str) -> Set[str]:
    """
    (REAL) Helper to get subdomains to check.
    This re-uses logic from footprint.py, but is simplified.
    A real implementation would pull this from the database or
    a full footprint scan.
    """
    console.print("[dim]Fetching common subdomains (www, api, blog, dev)...[/dim]")
    # In a real tool, we'd run a full subdomain enumeration.
    # For this example, we'll just check a few common ones.
    common_subs = {"www", "api", "blog", "dev", "store", "jobs", "support", "help"}
    return {f"{sub}.{target}" for sub in common_subs}


async def check_cname(subdomain: str) -> tuple[str, str] | None:
    """
    (REAL) Resolves the CNAME record for a subdomain.
    """
    try:
        resolver = dns.resolver.Resolver()
        answer = await asyncio.to_thread(resolver.resolve, subdomain, "CNAME")
        if answer:
            return (subdomain, str(answer[0].target))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        pass # No CNAME or subdomain doesn't exist
    except Exception as e:
        console.print(f"[dim]Error checking CNAME for {subdomain}: {e}[/dim]")
    return None


@covert_ops_app.command(
    name="check-takeover",
    help="Detect subdomain/cloud service hijack opportunities.",
)
async def check_takeover(
    target: Annotated[
        str,
        typer.Argument(
            help="The target domain to check for takeovers (e.g., 'example.com')."
        ),
    ],
):
    """
    (REAL) Checks for potential infrastructure takeovers by
    resolving CNAMEs and matching them against known vulnerable patterns.
    """
    console.print(f"[bold cyan]Checking for infrastructure takeover on: {target}[/bold cyan]")

    subdomains_to_check = await get_subdomains_for_takeover(target)
    
    findings = []
    
    with console.status("[cyan]Checking CNAME records for subdomains...[/cyan]"):
        tasks = [check_cname(sub) for sub in subdomains_to_check]
        cname_results = await asyncio.gather(*tasks)
        
        for result in cname_results:
            if not result:
                continue
            
            subdomain, cname = result
            for pattern, service in TAKEOVER_PATTERNS.items():
                if pattern in cname:
                    findings.append((subdomain, cname, service))
                    break # Move to the next subdomain

    if not findings:
        console.print("[green]No obvious takeover opportunities found.[/green]")
        return

    table = Table(title="[bold red]Potential Takeover Opportunities[/bold red]")
    table.add_column("Subdomain", style="cyan")
    table.add_column("CNAME Record", style="yellow")
    table.add_column("Vulnerable Service", style="magenta")

    module_data = []
    for sub, cname, service in findings:
        table.add_row(sub, cname, service)
        module_data.append(
            {"subdomain": sub, "cname": cname, "service": service}
        )
    
    console.print(table)

    # Store results in database
    try:
        store_data(
            target,
            "covert_ops_takeover",
            {"potential_takeovers": module_data},
        )
        console.print(f"Stored {len(module_data)} findings in database.")
    except Exception as e:
        console.print(f"[red]Error saving to database:[/red] {e}")


if __name__ == "__main__":
    asyncio.run(covert_ops_app())