"""
Cyber & Technology Intelligence Module for Chimera Intel.

Includes:
- Emerging Tech Monitoring (AI, Biotech, Quantum)
- Malware Sandbox Analysis
- Vulnerability & Zero-Day Hunting
"""

import typer
import asyncio
import re
import base64
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import httpx
from rich.panel import Panel
from chimera_intel.core.google_search import search as google_search_func
from chimera_intel.core.http_client import get_async_http_client
from chimera_intel.core.config_loader import API_KEYS
from chimera_intel.core.utils import console, save_or_print_results

logger = logging.getLogger(__name__)

# Create a new Typer application for Cyber/Tech Intelligence commands
cytech_intel_app = typer.Typer(
    name="cytech-intel",
    help="Cyber & Technology Intelligence Toolkit",
)

# --- Regex for hash detection ---
HASH_REGEX = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

def get_indicator_type(indicator: str) -> str:
    """Determines if an indicator is a hash or a URL."""
    if HASH_REGEX["md5"].match(indicator) or \
       HASH_REGEX["sha1"].match(indicator) or \
       HASH_REGEX["sha256"].match(indicator):
        return "hash"
    elif "://" in indicator or "." in indicator:
        # Simple check for URL/domain
        return "url"
    return "unknown"


async def analyze_indicator_virustotal(indicator: str) -> Dict[str, Any]:
    """
    (REAL) Integrates malware behavior analysis by fetching a report
    from the VirusTotal v3 API.
    """
    api_key = API_KEYS.virustotal_api_key
    if not api_key:
        return {"error": "VirusTotal API key (VIRUSTOTAL_API_KEY) not found."}
        
    headers = {"x-apikey": api_key}
    indicator_type = get_indicator_type(indicator)
    vt_url = None
    report = {}

    if indicator_type == "hash":
        vt_url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    elif indicator_type == "url":
        # VT API requires URL-safe base64 encoding for URL identifiers
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        return {"error": f"Unknown indicator type for: {indicator}"}

    async with get_async_http_client() as client:
        try:
            response = await client.get(vt_url, headers=headers)
            response.raise_for_status()
            
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            
            report = {
                "indicator": indicator,
                "type": indicator_type,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "last_analysis_date": datetime.fromtimestamp(data.get("last_analysis_date", 0)).isoformat() if data.get("last_analysis_date") else "N/A",
                "names": data.get("names", []),
                "reputation": data.get("reputation", "N/A"),
                "total_votes": data.get("total_votes", {}),
                "permalink": f"https://www.virustotal.com/gui/{'file' if indicator_type == 'hash' else 'url'}/{indicator}",
            }
            return report

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"error": f"Indicator not found in VirusTotal: {indicator}"}
            logger.error(f"VirusTotal API error: {e}")
            return {"error": f"VirusTotal API error: {e.response.text}"}
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}", exc_info=True)
            return {"error": f"An unexpected error occurred: {e}"}


@cytech_intel_app.command(
    name="emerging-tech",
    help="Track patents, products, and research in emerging tech.",
)
def emerging_tech(
    domain: str = typer.Option(
        ...,
        "--domain",
        help="The tech domain to track (e.g., 'AI', 'biotech', 'quantum').",
    ),
    topic: str = typer.Option(
        ..., "--topic", help="The specific topic (e.g., 'AlphaFold', 'quantum_encryption')."
    ),
):
    """
    Tracks patents, products, and research for a given emerging technology.
    """
    typer.echo(
        f"Tracking emerging tech in [bold]{domain}[/bold] on topic: [bold]{topic}[/bold]"
    )

    queries = [
        f"{domain} {topic} new patents",
        f"{domain} {topic} research papers 2024 2025",
        f"{domain} {topic} new products or startups",
    ]

    try:
        # Use the google_search tool
        typer.echo("Searching for recent developments...")
        results = google_search_func(queries=queries)

        if not results:
            typer.echo("No results found.")
            raise typer.Exit(code=0)

        # Process and display results (simplified)
        for i, result in enumerate(results[:5]):  # Show top 5
            typer.echo(f"\n--- Result {i + 1} ---")
            typer.echo(f"Title: {result.get('title')}")
            typer.echo(f"URL: {result.get('url')}")
            typer.echo(f"Snippet: {result.get('snippet')}")

    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


@cytech_intel_app.command(
    name="malware-sandbox",
    help="Get a real-time analysis report for a malware indicator from VirusTotal.",
)
def malware_sandbox(
    indicator: str = typer.Option(
        ...,
        "--indicator",
        help="The indicator to analyze (e.g., file hash or URL).",
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save results to a JSON file."
    ),
):
    """
    (REAL) Fetches a real-time malware analysis report from VirusTotal
    for a given file hash (SHA256, SHA1, MD5) or URL.
    """
    console.print(f"[bold cyan]Analyzing malware indicator:[/bold cyan] {indicator}")

    with console.status("[bold green]Querying VirusTotal v3 API...[/]"):
        report = asyncio.run(analyze_indicator_virustotal(indicator))

    if report.get("error"):
        console.print(f"[bold red]Error:[/bold red] {report['error']}")
        raise typer.Exit(code=1)

    # Display results
    malicious_score = report.get("malicious", 0) + report.get("suspicious", 0)
    
    if malicious_score > 5:
        color = "red"
        status = "MALICIOUS"
    elif malicious_score > 0:
        color = "yellow"
        status = "SUSPICIOUS"
    else:
        color = "green"
        status = "HARMLESS/UNDETECTED"

    panel_content = (
        f"Indicator: [bold]{report.get('indicator')}[/bold]\n"
        f"Type: [bold]{report.get('type')}[/bold]\n"
        f"Status: [bold {color}]{status}[/bold {color}]\n\n"
        f"Malicious: [red]{report.get('malicious')}[/red]\n"
        f"Suspicious: [yellow]{report.get('suspicious')}[/yellow]\n"
        f"Harmless: [green]{report.get('harmless')}[/green]\n"
        f"Undetected: {report.get('undetected')}\n\n"
        f"View Report: {report.get('permalink')}"
    )
    
    console.print(Panel(
        panel_content,
        title="[bold blue]VirusTotal Analysis Report[/bold blue]",
        border_style=color
    ))

    if output_file:
        save_or_print_results(report, output_file)


@cytech_intel_app.command(
    name="vuln-hunter",
    help="Track exploit disclosures and patches across software.",
)
def vulnerability_hunter(
    product: str = typer.Option(
        ...,
        "--product",
        help="The software or product to track (e.g., 'Microsoft Exchange', 'vCenter').",
    ),
):
    """
    Tracks recent vulnerability disclosures, exploits, and patches for a product.
    """
    typer.echo(f"Hunting for recent vulnerabilities in: {product}")

    queries = [
        f'"{product}" vulnerability disclosure 2024 2025',
        f'"{product}" zero-day exploit',
        f'"{product}" security patch OR update',
    ]

    try:
        # Use the google_search tool
        results = google_search_func(queries=queries)

        if not results:
            typer.echo(f"No recent vulnerability news found for: {product}")
            raise typer.Exit(code=0)

        typer.echo("\n--- Recent Vulnerability & Exploit News ---")
        for i, result in enumerate(results[:5]):  # Show top 5
            typer.echo(f"\n[bold]Finding {i + 1}[/bold]")
            typer.echo(f"Title: {result.get('title')}")
            typer.echo(f"Source: {result.get('url')}")
            typer.echo(f"Snippet: {result.get('snippet')}")

    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}", err=True)
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


if __name__ == "__main__":
    cytech_intel_app()