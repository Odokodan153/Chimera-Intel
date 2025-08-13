import typer
import os
import asyncio
import httpx
from rich.panel import Panel
from .utils import console, save_or_print_results
from .database import save_scan_to_db
from .config_loader import CONFIG # Import the loaded config

# --- Asynchronous Data Gathering Functions ---

async def get_tech_stack_builtwith(domain: str, api_key: str, client: httpx.AsyncClient) -> list:
    """Asynchronously retrieves website technology stack from the BuiltWith API."""
    if not api_key:
        console.print("[bold yellow]Warning:[/] BuiltWith API key not found. Skipping.")
        return []
    url = f"https://api.builtwith.com/v21/api.json?KEY={api_key}&LOOKUP={domain}"
    try:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
        technologies = []
        if "Results" in data and data["Results"]:
            for result in data["Results"]:
                for path in result.get("Result", {}).get("Paths", []):
                    for tech in path.get("Technologies", []):
                        technologies.append(tech.get("Name"))
        return list(set(technologies))
    except Exception as e:
        console.print(f"[bold red]Error (BuiltWith):[/] {e}")
        return []

async def get_tech_stack_wappalyzer(domain: str, api_key: str, client: httpx.AsyncClient) -> list:
    """Asynchronously retrieves website technology stack from the Wappalyzer API."""
    if not api_key:
        console.print("[bold yellow]Warning:[/] Wappalyzer API key not found. Skipping.")
        return []
    url = f"https://api.wappalyzer.com/v2/lookup/?urls=https://{domain}"
    headers = {"x-api-key": api_key}
    try:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        technologies = []
        if data and isinstance(data, list):
            for tech_info in data[0].get("technologies", []):
                technologies.append(tech_info.get("name"))
        return list(set(technologies))
    except Exception as e:
        console.print(f"[bold red]Error (Wappalyzer):[/] {e}")
        return []

async def get_traffic_similarweb(domain: str, api_key: str, client: httpx.AsyncClient) -> dict:
    """Asynchronously retrieves estimated website traffic from the Similarweb API."""
    if not api_key:
        return {"error": "Similarweb API key not found."}
    url = f"https://api.similarweb.com/v1/website/{domain}/total-traffic-and-engagement/visits?api_key={api_key}&granularity=monthly&main_domain_only=false"
    try:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": f"An unexpected error occurred with Similarweb: {e}"}

# --- Typer CLI Application ---

web_app = typer.Typer()

@web_app.command("run")
async def run_web_analysis(
    domain: str = typer.Argument(..., help="The target domain to analyze."),
    output_file: str = typer.Option(None, "--output", "-o", help="Save the results to a JSON file.")
):
    """Analyzes web-specific data asynchronously."""
    console.print(Panel(f"[bold blue]Starting Asynchronous Web Analysis for {domain}[/bold blue]", title="Chimera Intel | Web", border_style="blue"))
    
    builtwith_key = os.getenv("BUILTWITH_API_KEY")
    wappalyzer_key = os.getenv("WAPPALYZER_API_KEY")
    similarweb_key = os.getenv("SIMILARWEB_API_KEY")
    available_tech_sources = sum(1 for key in [builtwith_key, wappalyzer_key] if key)

    # Load the network timeout from the config file, with a default of 20 seconds
    network_timeout = CONFIG.get("network", {}).get("timeout", 20.0)

    async with httpx.AsyncClient(timeout=network_timeout) as client:
        console.print(" [cyan]>[/cyan] Fetching web data from all sources concurrently...")
        tasks = [
            get_tech_stack_builtwith(domain, builtwith_key, client),
            get_tech_stack_wappalyzer(domain, wappalyzer_key, client),
            get_traffic_similarweb(domain, similarweb_key, client)
        ]
        builtwith_tech, wappalyzer_tech, traffic_info = await asyncio.gather(*tasks)

    console.print(" [cyan]>[/cyan] Aggregating tech stack results...")
    all_tech = {}
    for tech in builtwith_tech:
        all_tech.setdefault(tech, []).append("BuiltWith")
    for tech in wappalyzer_tech:
        all_tech.setdefault(tech, []).append("Wappalyzer")

    scored_tech_results = []
    for tech, sources in sorted(all_tech.items()):
        num_found_sources = len(sources)
        confidence = "LOW"
        if num_found_sources == available_tech_sources and available_tech_sources > 1:
            confidence = "HIGH"
        scored_tech_results.append({"technology": tech, "sources": sources, "confidence": f"{confidence} ({num_found_sources}/{available_tech_sources} sources)"})

    tech_stack_report = {"total_unique": len(scored_tech_results), "results": scored_tech_results}

    results = {
        "domain": domain,
        "web_analysis": {
            "tech_stack": tech_stack_report,
            "traffic_info": traffic_info,
        }
    }
    
    console.print("\n[bold green]Web Analysis Complete![/bold green]")
    save_or_print_results(results, output_file)
    save_scan_to_db(target=domain, module="web_analyzer", data=results)